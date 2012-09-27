using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using System.Net;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.Security.Authentication.Web;

namespace Chorusde.OAuth.Twitter
{
    public sealed partial class MainPage : Page
    {
        private const string _requestTokenUrl = "https://api.twitter.com/oauth/request_token";
        private const string _redirectUrlBase = "https://api.twitter.com/oauth/authorize?oauth_token=";
        private const string _accessTokenUrl = "https://api.twitter.com/oauth/access_token";

        public MainPage()
        {
            this.InitializeComponent();
        }

        /// <summary>
        /// 実行ボタンクリック後の制御
        /// </summary>
        private async void _btExecute_Click(object sender, RoutedEventArgs e)
        {
            DebugPrint("リクエストトークンの取得要求開始...");
            var requestTokenResponse = await GetRequetToken();
            if (requestTokenResponse != null)
            {
                DebugPrint("リクエストトークンの取得成功");
                DebugPrint("レスポンス: " + requestTokenResponse);
            }
            else
            {
                return;
            }
            
            DebugPrint("Web認証実行開始...");
            var webAuthResponse = await RedirectUser(requestTokenResponse);
            if (webAuthResponse != null)
            {
                DebugPrint("Web認証成功");
                DebugPrint("レスポンス: " + webAuthResponse);
            }
            else
            {
                return;
            }
            
            DebugPrint("アクセストークンの取得要求開始...");
            var accessTokenResponse = await GetAccessToken(webAuthResponse);
            if (accessTokenResponse != null)
            {
                DebugPrint("アクセストークンの取得成功");
                DebugPrint("レスポンス: " + accessTokenResponse);
            }
            else
            {
                return;
            }
        }

        /// <summary>
        /// リクエストトークンの取得
        /// </summary>
        private async Task<string> GetRequetToken()
        {
            string requestTokenResponse = null;

            try
            {
                //タイムスタンプ（UNIX時間）の生成
                TimeSpan sinceEpoch = (DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime());
            
                //ユニークな認証トークンの生成
                var rand = new Random();
                Int32 Nonce = rand.Next(1000000000);

                //シグネチャ用文字列の生成
                String SigBaseStringParams = "oauth_callback=" + Uri.EscapeDataString(_tbCallbackUrl.Text);
                SigBaseStringParams += "&" + "oauth_consumer_key=" + _tbConsumerKey.Text;
                SigBaseStringParams += "&" + "oauth_nonce=" + Nonce.ToString();
                SigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
                SigBaseStringParams += "&" + "oauth_timestamp=" + Math.Round(sinceEpoch.TotalSeconds);
                SigBaseStringParams += "&" + "oauth_version=1.0";
                String SigBaseString = "POST&";
                SigBaseString += Uri.EscapeDataString(_requestTokenUrl) + "&" + Uri.EscapeDataString(SigBaseStringParams);

                //シグネチャ用文字列をハッシュ化(HMAC_SHA1)しシグネチャを生成
                IBuffer KeyMaterial = CryptographicBuffer.ConvertStringToBinary(_tbConsumerSecret.Text + "&", BinaryStringEncoding.Utf8);
                MacAlgorithmProvider HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
                CryptographicKey MacKey = HmacSha1Provider.CreateKey(KeyMaterial);
                IBuffer DataToBeSigned = CryptographicBuffer.ConvertStringToBinary(SigBaseString, BinaryStringEncoding.Utf8);
                IBuffer SignatureBuffer = CryptographicEngine.Sign(MacKey, DataToBeSigned);
                String Signature = CryptographicBuffer.EncodeToBase64String(SignatureBuffer);

                //認証要求のためのデータ文字列を生成
                String DataToPost = "OAuth oauth_callback=\"" + Uri.EscapeDataString(_tbCallbackUrl.Text) + "\"";
                DataToPost += ", oauth_consumer_key=\"" + _tbConsumerKey.Text + "\"";
                DataToPost += ", oauth_nonce=\"" + Nonce.ToString() + "\"";
                DataToPost += ", oauth_signature_method=\"HMAC-SHA1\"";
                DataToPost += ", oauth_timestamp=\"" + Math.Round(sinceEpoch.TotalSeconds) + "\"";
                DataToPost += ", oauth_version=\"1.0\"";
                DataToPost += ", oauth_signature=\"" + Uri.EscapeDataString(Signature) + "\"";

                //リクエストトークンの取得要求をポスト
                HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(_requestTokenUrl);
                Request.Method = "POST";
                Request.Headers["Authorization"] = DataToPost;
                HttpWebResponse Response = (HttpWebResponse)await Request.GetResponseAsync();
                StreamReader ResponseDataStream = new StreamReader(Response.GetResponseStream());
                requestTokenResponse = await ResponseDataStream.ReadToEndAsync();
            }
            catch (Exception ex)
            {
                DebugPrint("Error: " + ex.Message);
            }

            return requestTokenResponse;
        }

        /// <summary>
        /// ユーザをTwitterの認証画面にリダイレクトしWeb認証を実行
        /// </summary>
        /// <param name="responseTokenResponse">リクエストトークン要求のレスポンス</param>
        private async Task<string> RedirectUser(string requestTokenResponse)
        {
            string webAuthResponse = null;

            try
            {
                if (requestTokenResponse != null)
                {
                    //リクエストトークン要求のレスポンスからトークンを取得
                    String oauth_token = null;
                    var responseArray = requestTokenResponse.Split('&');
                    foreach (string paramArray in responseArray)
                    {
                        var paramSet = paramArray.Split('=');
                        switch (paramSet[0])
                        {
                            case "oauth_token":
                                oauth_token = paramSet[1];
                                break;
                        }
                    }

                    if (oauth_token != null)
                    {
                        //ユーザをTwitterの認証画面にリダイレクトしWeb認証を開始
                        var redirectUrl = _redirectUrlBase + oauth_token;
                        System.Uri StartUri = new Uri(redirectUrl);
                        System.Uri EndUri = new Uri(_tbCallbackUrl.Text);
                        WebAuthenticationResult WebAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, StartUri,EndUri);

                        //Web認証のレスポンスを取得
                        if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                        {
                            webAuthResponse = WebAuthenticationResult.ResponseData.ToString();
                        }
                        else if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.ErrorHttp)
                        {
                            DebugPrint("Error: " + WebAuthenticationResult.ResponseErrorDetail.ToString());
                        }
                        else
                        {
                            DebugPrint("Error: " + WebAuthenticationResult.ResponseStatus.ToString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                DebugPrint("Error: " + ex.Message);
            }

            return webAuthResponse;
        }

        /// <summary>
        /// アクセストークンの取得
        /// </summary>
        /// <param name="webAuthResponse">Web認証のレスポンス</param>
        private async Task<string> GetAccessToken(string webAuthResponse)
        {
            string accessTokenResponse = null;

            try
            {
                if (webAuthResponse != null)
                {
                    //Web認証のレスポンスからトークンを取得
                    string oauth_token = null;
                    string oauth_verifier = null;
                    var responseParts = webAuthResponse.Split('?');
                    var responseArray = responseParts[responseParts.Length - 1].Split('&');
                    foreach (string paramArray in responseArray)
                    {
                        var paramSet = paramArray.Split('=');
                        switch (paramSet[0])
                        {
                            case "oauth_token":
                                oauth_token = paramSet[1];
                                break;
                            case "oauth_verifier":
                                oauth_verifier = paramSet[1];
                                break;
                        }
                    }

                    //タイムスタンプ（UNIX時間）の生成
                    TimeSpan sinceEpoch = (DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime());

                    //ユニークな認証トークンの生成
                    var rand = new Random();
                    Int32 Nonce = rand.Next(1000000000);

                    //シグネチャ用文字列の生成
                    String SigBaseStringParams = "oauth_consumer_key=" + _tbConsumerKey.Text;
                    SigBaseStringParams += "&" + "oauth_nonce=" + Nonce.ToString();
                    SigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
                    SigBaseStringParams += "&" + "oauth_timestamp=" + Math.Round(sinceEpoch.TotalSeconds);
                    SigBaseStringParams += "&" + "oauth_token=" + oauth_token;
                    SigBaseStringParams += "&" + "oauth_version=1.0";
                    String SigBaseString = "POST&";
                    SigBaseString += Uri.EscapeDataString(_accessTokenUrl) + "&" + Uri.EscapeDataString(SigBaseStringParams);

                    //シグネチャ用文字列をハッシュ化(HMAC_SHA1)しシグネチャを生成
                    IBuffer KeyMaterial = CryptographicBuffer.ConvertStringToBinary(_tbConsumerSecret.Text + "&", BinaryStringEncoding.Utf8);
                    MacAlgorithmProvider HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
                    CryptographicKey MacKey = HmacSha1Provider.CreateKey(KeyMaterial);
                    IBuffer DataToBeSigned = CryptographicBuffer.ConvertStringToBinary(SigBaseString, BinaryStringEncoding.Utf8);
                    IBuffer SignatureBuffer = CryptographicEngine.Sign(MacKey, DataToBeSigned);
                    String Signature = CryptographicBuffer.EncodeToBase64String(SignatureBuffer);

                    //認証要求のためのデータ文字列を生成
                    String DataToPost = "OAuth oauth_consumer_key=\"" + _tbConsumerKey.Text + "\"";
                    DataToPost += ", oauth_nonce=\"" + Nonce.ToString() + "\"";
                    DataToPost += ", oauth_signature_method=\"HMAC-SHA1\"";
                    DataToPost += ", oauth_timestamp=\"" + Math.Round(sinceEpoch.TotalSeconds) + "\"";
                    DataToPost += ", oauth_token=\"" + oauth_token + "\"";
                    DataToPost += ", oauth_version=\"1.0\"";
                    DataToPost += ", oauth_signature=\"" + Uri.EscapeDataString(Signature) + "\"";

                    //リクエストトークンの取得要求をポスト
                    HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(_accessTokenUrl);
                    Request.Method = "POST";
                    Request.Headers["Authorization"] = DataToPost;

                    var stream = new StreamWriter(await Request.GetRequestStreamAsync());
                    await stream.WriteAsync(oauth_verifier);

                    HttpWebResponse Response = (HttpWebResponse)await Request.GetResponseAsync();
                    if (Response.StatusCode == HttpStatusCode.OK)
                    {
                        using (StreamReader ResponseDataStream = new StreamReader(Response.GetResponseStream()))
                        {
                            accessTokenResponse = await ResponseDataStream.ReadToEndAsync();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                DebugPrint("Error: " + ex.Message);
            }

            return accessTokenResponse;
        }

        /// <summary>
        /// メッセージ出力
        /// </summary>
        private void DebugPrint(string s)
        {
            _tbDebug.Text += s + "\r\n";
        }
    }
}
