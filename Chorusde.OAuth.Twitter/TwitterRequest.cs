using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace Chorusde.OAuth.Twitter
{
    public class TwitterRequest
    {
        #region 定数値
        private const string _pName_oauth_callback = "oauth_callback";
        private const string _pName_oauth_consumer_key = "oauth_consumer_key";
        private const string _pName_oauth_nonce = "oauth_nonce";
        private const string _pName_oauth_signature = "oauth_signature";
        private const string _pName_oauth_signature_method = "oauth_signature_method";
        private const string _pName_oauth_timestamp = "oauth_timestamp";
        private const string _pName_oauth_token = "oauth_token";
        private const string _pName_oauth_version = "oauth_version";
        private const string _pName_oauth_verifier = "oauth_verifier";
        private const string _pName_status = "status";
        private const string _requestTokenUrl = "https://api.twitter.com/oauth/request_token";
        private const string _redirectUrlBase = "https://api.twitter.com/oauth/authorize?oauth_token=";
        private const string _accessTokenUrl = "https://api.twitter.com/oauth/access_token";
        private const string _updateStatusUrl = "https://api.twitter.com/1/statuses/update.json";
        private const string _macAlgorithm = "HMAC_SHA1";
        private const string _oauth_signature_method = "HMAC-SHA1";
        private const string _oauth_version = "1.0";
        #endregion

        private string _oauth_consumer_key;
        private string _oauth_consumer_secret;
        private string _oauth_callback;

        /// <summary>
        /// コンストラクタ
        /// </summary>
        public TwitterRequest(string oauth_consumer_key, string oauth_consumer_secret, string oauth_callback)
        {
            _oauth_consumer_key = oauth_consumer_key;
            _oauth_consumer_secret = oauth_consumer_secret;
            _oauth_callback = oauth_callback;            
        }

        #region OAuth
        public async Task<string> GetAuthorization()
        {
            string response = String.Empty;

            //リクエストトークンの取得
            response = await GetRequestToken();

            //リクエストトークン要求のレスポンスからトークンを取得
            string request_token = null;
            var requestResponseArray = response.Split('&');
            foreach (string paramArray in requestResponseArray)
            {
                var paramSet = paramArray.Split('=');
                switch (paramSet[0])
                {
                    case "oauth_token":
                        request_token = paramSet[1];
                        break;
                }
            }

            //ユーザーのリダイレクト
            response = await RedirectUser(request_token);

            //Web認証のレスポンスからトークンを取得
            string oauth_token = null;
            string oauth_verifier = null;
            var webResponseParts = response.Split('?');
            var webResponseArray = webResponseParts[webResponseParts.Length - 1].Split('&');
            foreach (string paramArray in webResponseArray)
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

            //アクセストークンを取得
            response = await GetAccessToken(oauth_token, oauth_verifier);

            return response;
        }

        /// <summary>
        /// リクエストトークンの取得
        /// </summary>
        private async Task<string> GetRequestToken()
        {
            string response = String.Empty;

            //パラメーターディクショナリの作成
            SortedDictionary<string, string> paramDictionary = new SortedDictionary<string, string>();

            //パラメーターの追加
            AddPercentEncodedItem(paramDictionary, _pName_oauth_callback, _oauth_callback);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_consumer_key, _oauth_consumer_key);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_nonce, GenerateNonce());
            AddPercentEncodedItem(paramDictionary, _pName_oauth_signature_method, _oauth_signature_method);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_timestamp, GenerateTimeStamp());
            AddPercentEncodedItem(paramDictionary, _pName_oauth_version, _oauth_version);

            //シグネチャを生成しパラメーターに追加
            string signature = GenerateSignature(paramDictionary, _requestTokenUrl);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_signature, signature);
            
            //リクエストヘッダーを生成
            string header = GenerateHeader(paramDictionary);

            //リクエストをポスト
            response = await PostReuqest(_requestTokenUrl, header);

            return response;
        }

        /// <summary>
        /// ユーザをTwitterの認証画面にリダイレクトしWeb認証を実行
        /// </summary>
        /// <param name="responseTokenResponse">リクエストトークン要求のレスポンス</param>
        private async Task<string> RedirectUser(string request_token)
        {
            string response = null;

            //ユーザをTwitterの認証画面にリダイレクトしWeb認証を開始
            var redirectUrl = _redirectUrlBase + request_token;
            System.Uri StartUri = new Uri(redirectUrl);
            System.Uri EndUri = new Uri(_oauth_callback);
            var WebAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, StartUri, EndUri);

            //Web認証のレスポンスを取得
            if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
            {
                response = WebAuthenticationResult.ResponseData.ToString();
            }

            return response;
        }

        /// <summary>
        /// アクセストークンの取得
        /// </summary>
        private async Task<string> GetAccessToken(string oauth_token, string oauth_verifier)
        {
            string response = String.Empty;

            //パラメーターディクショナリの作成
            SortedDictionary<string, string> paramDictionary = new SortedDictionary<string, string>();

            //パラメーターの追加
            AddPercentEncodedItem(paramDictionary, _pName_oauth_callback, _oauth_callback);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_consumer_key, _oauth_consumer_key);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_nonce, GenerateNonce());
            AddPercentEncodedItem(paramDictionary, _pName_oauth_signature_method, _oauth_signature_method);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_timestamp, GenerateTimeStamp());
            AddPercentEncodedItem(paramDictionary, _pName_oauth_version, _oauth_version);

            //認証トークンをパラメーターディクショナリに追加
            AddPercentEncodedItem(paramDictionary, _pName_oauth_token, oauth_token);

            //シグネチャを生成しパラメーターに追加
            string signature = GenerateSignature(paramDictionary, _accessTokenUrl);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_signature, signature);

            //リクエストヘッダーを生成
            string header = GenerateHeader(paramDictionary);

            //リクエストデータ（oauth_verifier）文字列を生成
            string requestData = Uri.EscapeDataString(_pName_oauth_verifier) + "=" + Uri.EscapeDataString(oauth_verifier);

            //リクエストをポスト
            response = await PostReuqest(_accessTokenUrl, header, requestData);

            return response;
        }
        #endregion

        #region API 利用
        /// <summary>
        /// ステータスの更新（つぶやく）
        /// </summary>
        public async Task<string> UpdateStatus(string oauth_token, string oauth_token_secret, string tweetString)
        {
            string response = String.Empty;

            //パラメーターディクショナリの作成
            SortedDictionary<string, string> paramDictionary = new SortedDictionary<string, string>();

            //パラメーターの追加
            AddPercentEncodedItem(paramDictionary, _pName_oauth_consumer_key, _oauth_consumer_key);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_nonce, GenerateNonce());
            AddPercentEncodedItem(paramDictionary, _pName_oauth_signature_method, _oauth_signature_method);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_timestamp, GenerateTimeStamp());
            AddPercentEncodedItem(paramDictionary, _pName_oauth_version, _oauth_version);

            //認証トークンをパラメーターディクショナリに追加
            AddPercentEncodedItem(paramDictionary, _pName_oauth_token, oauth_token);

            //ツイート文字列をパラメータディクショナリに追加
            AddPercentEncodedItem(paramDictionary, _pName_status, tweetString);

            //シグネチャを生成しパラメーターに追加
            string signature = GenerateSignature(paramDictionary, _updateStatusUrl, oauth_token_secret);
            AddPercentEncodedItem(paramDictionary, _pName_oauth_signature, signature);

            //ツイート文字列をパラメーターから除外し、ヘッダーを生成
            paramDictionary.Remove(_pName_status);
            string header = GenerateHeader(paramDictionary);

            //リクエストデータ（ツイート）文字列を生成
            string requestData = Uri.EscapeDataString(_pName_status) + "=" + Uri.EscapeDataString(tweetString);

            //リクエストをポスト
            response = await PostReuqest(_updateStatusUrl, header, requestData);

            return response;
        }
        #endregion

        /// <summary>
        /// リクエストをポスト
        /// </summary>
        private async Task<string> PostReuqest(string destUrl, string header, string requestDataString = null)
        {
            string response = String.Empty;

            //リクエストトークンの取得要求をポスト
            HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(destUrl);
            Request.Method = "POST";
            Request.Headers["Authorization"] = header;

            //リクエストデータが存在する場合はストリームに書き込み
            if (requestDataString != null)
            {
                using (StreamWriter streamWriter = new StreamWriter(await Request.GetRequestStreamAsync()))
                {
                    await streamWriter.WriteAsync(requestDataString);
                }
            }

            //リクエストを実行しレスポンスを取得
            HttpWebResponse Response = (HttpWebResponse)await Request.GetResponseAsync();
            if (Response.StatusCode == HttpStatusCode.OK)
            {
                using (StreamReader ResponseDataStream = new StreamReader(Response.GetResponseStream()))
                {
                    response = await ResponseDataStream.ReadToEndAsync();
                }
            }

            return response;
        }

        /// <summary>
        /// シグネチャの生成
        /// </summary>
        private string GenerateSignature(SortedDictionary<string, string> paramDictionary, string reqestUrl, string oAuthTokenSecret=null)
        {
            string signature = String.Empty;

            //パラメータディクショナリ内の要素を結合しシグネチャのベースとなる文字列を生成
            string baseStrParams = String.Empty;
            foreach (var kvp in paramDictionary)
            {
                baseStrParams += (baseStrParams.Length > 0 ? "&" : String.Empty) + kvp.Key + "=" + kvp.Value;
            }
            string baseStr = "POST&" + Uri.EscapeDataString(reqestUrl) + "&" + Uri.EscapeDataString(baseStrParams);

            //デジタル署名用キーを生成するためのキー文字列を生成
            string stringKey = Uri.EscapeDataString(_oauth_consumer_secret) + "&";
            if (!String.IsNullOrEmpty(oAuthTokenSecret))
            {
                stringKey += Uri.EscapeDataString(oAuthTokenSecret);
            }

            //キー文字列をバッファに変換
            IBuffer KeyMaterial = CryptographicBuffer.ConvertStringToBinary(stringKey, BinaryStringEncoding.Utf8);

            //MACアルゴリズムを指定
            MacAlgorithmProvider macAlgorithm = MacAlgorithmProvider.OpenAlgorithm(_macAlgorithm);

            //デジタル署名用キーの生成
            CryptographicKey MacKey = macAlgorithm.CreateKey(KeyMaterial);

            //ベース文字列をバッファに変換
            IBuffer DataToBeSigned = CryptographicBuffer.ConvertStringToBinary(baseStr, BinaryStringEncoding.Utf8);

            //ベース文字列をデジタル署名
            IBuffer SignatureBuffer = CryptographicEngine.Sign(MacKey, DataToBeSigned);

            //Base64エンコードにてシグネチャを取得
            signature = CryptographicBuffer.EncodeToBase64String(SignatureBuffer);

            return signature;
        }
        
        /// <summary>
        /// ヘッダー文字列の生成
        /// </summary>
        private string GenerateHeader(SortedDictionary<string, string> paramDictionary)
        {
            string header = string.Empty;

            //パラメーターディクショナリ内の要素を結合しヘッダー文字列を生成
            string headerParams = String.Empty;
            foreach (var kvp in paramDictionary)
            {
                headerParams += (headerParams.Length > 0 ? ", " : string.Empty) + kvp.Key + "=\"" + kvp.Value + "\"";
            }
            header = "OAuth " + headerParams;

            return header;
        }

        /// <summary>
        /// パラメーター名および値をパーセントエンコードしてディクショナリに追加
        /// </summary>
        private void AddPercentEncodedItem(SortedDictionary<string, string> dictionary,　string key, string keyValue)
        {
            dictionary.Add(Uri.EscapeDataString(key), Uri.EscapeDataString(keyValue));
        }

        /// <summary>
        /// リクエストを識別するための一意なトークンを生成
        /// </summary>
        private string GenerateNonce()
        {
            var rand = new Random();
            return (rand.Next(1000000000)).ToString();
        }

        /// <summary>
        /// リクエストを識別するためのタイムスタンプ（UNIX時間）を生成
        /// </summary>
        private string GenerateTimeStamp()
        {
            return (Math.Round((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds)).ToString();
        }
    }
}
