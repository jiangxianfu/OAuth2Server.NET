using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OAuth2Server
{
    public class MSOAuth2 : OAuth2
    {
        protected override bool CheckClientCredentials(string client_id, string client_secret)
        {
            //SELECT client_secret FROM clients WHERE client_id = :client_id
            throw new NotImplementedException();
        }



        protected override bool CheckUserCredentials(string client_id, string username, string password)
        {
            //根据ClientId,验证用户信息
            throw new NotImplementedException();
        }

        protected override string GetRedirectUri(string client_id)
        {
            //SELECT redirect_uri FROM clients WHERE client_id = :client_id
            throw new NotImplementedException();
        }
        protected override AuthTokenInfo GetAccessToken(string access_token)
        {
            //SELECT client_id, expires, scope FROM tokens WHERE oauth_token = :oauth_token
            throw new NotImplementedException();
        }

        protected override void SetAccessToken(string oauth_token, string client_id, TimeSpan expires, string scope)
        {
            //INSERT INTO tokens (oauth_token, client_id, expires, scope) VALUES (:oauth_token, :client_id, :expires, :scope)
            throw new NotImplementedException();
        }

        protected override AuthCodeInfo GetAuthCode(string code)
        {
            //SELECT code, client_id, redirect_uri, expires, scope FROM auth_codes WHERE code = :code
            throw new NotImplementedException();
        }
        protected override void SetAuthCode(string code, string client_id, string redirect_uri, TimeSpan expires, string scope)
        {
            //INSERT INTO auth_codes (code, client_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :redirect_uri, :expires, :scope)
            throw new NotImplementedException();
        }

        public void AddClient(string client_id, string client_secret, string redirect_uri)
        {
            //INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES (:client_id, :client_secret, :redirect_uri)
        }
    }
}