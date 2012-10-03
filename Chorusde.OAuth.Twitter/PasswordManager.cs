using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Credentials;

namespace Chorusde.OAuth.Twitter
{
    class PasswordManager
    {
        private PasswordVault _passwordVault;
        private string _resource;

        /// <summary>
        /// コンストラクタ
        /// </summary>
        public PasswordManager(string resource)
        {
            _passwordVault = new PasswordVault();
            _resource = resource;
        }

        /// <summary>
        /// 指定ユーザーの認証情報情報の保存
        /// </summary>
        public void SaveCredential(string userName, string password)
        {
            if (!String.IsNullOrEmpty(userName) && !String.IsNullOrEmpty(password))
            {
                _passwordVault.Add(new PasswordCredential(_resource, userName, password));
            }
            else
            {
                throw new ArgumentNullException();
            }
        }

        /// <summary>
        /// 指定ユーザーの認証情報を取得
        /// </summary>
        private PasswordCredential RetrieveCredentialByUser(string userName)
        {
            try
            {
                var credential = _passwordVault.Retrieve(_resource, userName);
                return credential;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        /// <summary>
        /// アプリケーションのすべての認証情報を取得
        /// </summary>
        private IReadOnlyList<PasswordCredential> RetrieveCredentialByApp()
        {
            try
            {
                var credentials = _passwordVault.FindAllByResource(_resource);
                return credentials;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        /// <summary>
        /// 指定ユーザのパスワードを取得
        /// </summary>
        public string GetPassword(string userName)
        {
            if (!String.IsNullOrEmpty(userName))
            {
                PasswordCredential credential = RetrieveCredentialByUser(userName);
                if (credential != null)
                {
                    return credential.Password;
                }
                else
                {
                    return null;
                }
            }
            else
            {
                throw new ArgumentNullException();
            }
        }

        /// <summary>
        /// 指定ユーザーの認証情報削除
        /// </summary>
        public bool RemoveCredential(string userName)
        {
            if (!String.IsNullOrEmpty(userName))
            {
                var credential = RetrieveCredentialByUser(userName);
                if (credential != null)
                {
                    _passwordVault.Remove(credential);
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                throw new ArgumentNullException();
            }
        }

        /// <summary>
        /// すべての認証情報を削除
        /// </summary>
        public bool RemoveAllCredential()
        {
            var credentials = RetrieveCredentialByApp();
            if (credentials != null)
            {
                foreach(PasswordCredential pc in credentials)
                {
                    _passwordVault.Remove(pc);
                }
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
