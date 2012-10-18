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
using Windows.Security.Credentials;

namespace Chorusde.OAuth.Twitter
{
    public sealed partial class MainPage : Page
    {
        private const string _consumer_key = "コンシューマーキー（アプリケーションID）";
        private const string _consumer_key_secret = "アプリケーション秘密鍵";
        private const string _valutResource = "Chorusde.OAuth.Twitter";
        private const string _pName_oauth_token = "oauth_token";
        private const string _pName_oauth_token_secret = "oauth_token_secret";
        private const string _pName_oauth_user_id = "user_id";
        private const string _pName_screen_name = "screen_name";

        TwitterRequest _twitterRequest;
        private PasswordManager _passwordManager;
        private Dictionary<string, string> _oauthDictionary;

        public MainPage()
        {
            this.InitializeComponent();

            //コールバックURLの作成
            var callbackUrl = WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString();

            _twitterRequest = new TwitterRequest(_consumer_key, _consumer_key_secret, callbackUrl);
            _passwordManager = new PasswordManager(_valutResource);
        }

        #region ユーザーオペレーション制御
        /// <summary>
        /// 実行ボタンクリック後の制御
        /// </summary>
        private async void _btAuthExecute_Click(object sender, RoutedEventArgs e)
        {
            if (!String.IsNullOrEmpty(_tbTwitterID.Text))
            {
                //保存されている認証情報の読み込み
                var oauthResponse = _passwordManager.GetPassword(_tbTwitterID.Text);

                if (!String.IsNullOrEmpty(oauthResponse) && initlizeOAuthInfo(oauthResponse))
                {
                    DebugPrint("保存されている認証情報を読み込みました");
                    Authorized();
                }
                else
                {
                    //認証情報が見つからない場合は、認証開始
                    DebugPrint("保存されている認証情報はありません。OAuth要求を開始しています...");
                    string response = await _twitterRequest.GetAuthorization();

                    if (!String.IsNullOrEmpty(response) && initlizeOAuthInfo(response))
                    {
                        try
                        {
                            if (_tbTwitterID.Text == _oauthDictionary[_pName_screen_name])
                            {
                                //入力されたユーザIDと取得した認証情報が一致する場合は認証情報を取得して保存
                                Authorized();
                                _passwordManager.SaveCredential(_tbTwitterID.Text, response);
                                DebugPrint("認証情報を保存しました");
                            }
                            else
                            {
                                _passwordManager.RemoveCredential(_oauthDictionary[_pName_screen_name]);
                                DebugPrint("指定したユーザーIDが取得した認証情報と一致しません");
                            }
                        }
                        catch (Exception ex)
                        {
                            DebugPrint(ex.Message);
                        }
                    }
                }
            }
            else
            {
                DebugPrint("TwitterのユーザーIDが入力されていません");
            }
        }

        /// <summary>
        /// 認証情報クリアボタンクリック時の制御
        /// </summary>
        private void _btReset_Click(object sender, RoutedEventArgs e)
        {
            //保存されている認証情報を削除
            if (_passwordManager.RemoveAllCredential())
            {
                DebugPrint("保存されているすべての認証情報をクリアしました");
            }
            else
            {
                DebugPrint("保存されている認証情報はありません");
            }

            _btTweet.IsEnabled = false;
            _btAuthExecute.IsEnabled = true;
        }

        /// <summary>
        /// つぶやくボタンクリック後
        /// </summary>
        private async void _btTweet_Click(object sender, RoutedEventArgs e)
        {
            if (!String.IsNullOrEmpty(_tbTweetText.Text))
            {
                try
                {
                    var result = await _twitterRequest.UpdateStatus(_oauthDictionary[_pName_oauth_token], _oauthDictionary[_pName_oauth_token_secret], _tbTweetText.Text);
                    DebugPrint("ステータスの更新（ツイート）に成功しました");
                }
                catch (Exception ex)
                {
                    DebugPrint(ex.Message);
                }
            }
            else
            {
                DebugPrint("ツイートの内容を入力してください");
            }
        }
        #endregion

        /// <summary>
        /// OAuth 認証情報を初期化
        /// </summary>
        private bool initlizeOAuthInfo(string oAuthResponse)
        {
            string oauth_token = String.Empty;
            string oauth_token_secret = String.Empty;
            string user_id = String.Empty;
            string screen_name = String.Empty;

            //リクエストからパラメーターを取得
            var responseArray = oAuthResponse.Split('&');
            foreach (string paramArray in responseArray)
            {
                var paramSet = paramArray.Split('=');
                switch (paramSet[0])
                {
                    case _pName_oauth_token:
                        oauth_token = paramSet[1];
                        break;
                    case _pName_oauth_token_secret:
                        oauth_token_secret = paramSet[1];
                        break;
                    case _pName_oauth_user_id:
                        user_id = paramSet[1];
                        break;
                    case _pName_screen_name:
                        screen_name = paramSet[1];
                        break;
                }
            }

            //パラメーターをディクショナリに保持
            if (!String.IsNullOrEmpty(oauth_token) && !String.IsNullOrEmpty(oauth_token_secret) && !String.IsNullOrEmpty(user_id) && !String.IsNullOrEmpty(screen_name))
            {
                _oauthDictionary = new Dictionary<string, string>();
                _oauthDictionary.Add(_pName_oauth_token, oauth_token);
                _oauthDictionary.Add(_pName_oauth_token_secret, oauth_token_secret);
                _oauthDictionary.Add(_pName_oauth_user_id, user_id);
                _oauthDictionary.Add(_pName_screen_name, screen_name);
                return true;
            }

            return false;
        }

        //認証成功時
        private void Authorized()
        {
            DebugPrint("認証に成功しました");
            _btAuthExecute.IsEnabled = false;
            _btTweet.IsEnabled = true;
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
