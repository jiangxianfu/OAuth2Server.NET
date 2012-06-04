using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
namespace OAuth2Server
{
    public class RequestAuthorizeParams
    {
        public string ClientId { get; set; }
        public string ResponseType { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
        public string Scope { get; set; }
    }
    public class AuthCodeInfo
    {
        public string Code { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public TimeSpan Expires { get; set; }
        public string Scopes { get; set; }
    }
    public class AuthTokenInfo
    {
        public string AccessToken { get; set; }
        public string ClientId { get; set; }
        public TimeSpan Expires { get; set; }
        public string Scopes { get; set; }
    }
    /// <summary>
    /// 消费者
    /// </summary>
    public class ClientInfo
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string RedirectUri { get; set; }
    }
    public class RequestAccessTokenParams
    {
        public string GrantType { get; set; }
        public string Scope { get; set; }
        public string Code { get; set; }
        public string RedirectUri { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }
    public class ResponseOAuth2Params
    {
        public string ResponseType { get; set; }
        public string AuthCode { get; set; }
        public string AccessToken { get; set; }
        public string ExpiresIn { get; set; }
        public string State { get; set; }
        public string Error { get; set; }
    }

    public abstract class OAuth2
    {
        private HttpContext current = HttpContext.Current;
        public OAuth2()
        {

        }
        #region public
        public RequestAuthorizeParams GetAuthorizeParams()
        {
            RequestAuthorizeParams paramters = new RequestAuthorizeParams();
            paramters.ClientId = current.Request.QueryString[Constants.ClientIdParameter];
            paramters.ResponseType = current.Request.QueryString[Constants.ResponseTypeParameter];
            paramters.RedirectUri = current.Request.QueryString[Constants.RedirectUriParameter];
            paramters.State = current.Request.QueryString[Constants.StateParameter];
            paramters.Scope = current.Request.QueryString[Constants.ScopeParameter];

            //// Make sure a valid client id was supplied
            if (string.IsNullOrEmpty(paramters.ClientId))
            {
                if (string.IsNullOrEmpty(paramters.RedirectUri))
                {
                    DoRedirectUriError(Constants.OAUTH2_ERROR_INVALID_CLIENT, null, current.Request.RawUrl, paramters.State);
                }
                DoRedirectUriError(Constants.OAUTH2_HTTP_FOUND, Constants.OAUTH2_ERROR_INVALID_CLIENT, null, paramters.State);
            }

            //// redirect_uri is not required if already established via other channels
            //// check an existing redirect URI against the one supplied
            string redirect_uri = GetRedirectUri(paramters.ClientId);

            //// getRedirectUri() should return FALSE if the given client ID is invalid
            //// this probably saves us from making a separate db call, and simplifies the method set
            if (string.IsNullOrEmpty(redirect_uri))

                DoRedirectUriError(Constants.OAUTH2_ERROR_INVALID_CLIENT, null, null, paramters.State);

            //// At least one of: existing redirect URI or input redirect URI must be specified
            if (string.IsNullOrEmpty(paramters.RedirectUri))
                DoRedirectUriError(Constants.OAUTH2_HTTP_FOUND, Constants.OAUTH2_ERROR_INVALID_REQUEST, null, paramters.State);

            //// If there's an existing uri and one from input, verify that they match
            if (!redirect_uri.Equals(paramters.RedirectUri, StringComparison.CurrentCultureIgnoreCase))
            {
                DoRedirectUriError(Constants.OAUTH2_ERROR_REDIRECT_URI_MISMATCH, null, null, paramters.State);
            }

            //// type and client_id are required
            if (string.IsNullOrEmpty(paramters.ResponseType))
                DoRedirectUriError(Constants.OAUTH2_ERROR_INVALID_REQUEST, Constants.OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE, null, paramters.State);


            //// Check requested auth response type against the list of supported types
            List<string> responseTypes = GetSupportedAuthResponseTypes();
            if (!responseTypes.Contains(paramters.ResponseType))
                DoRedirectUriError(Constants.OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE, null, null, paramters.State);

            
            //// Validate that the requested scope is supported
            if (!string.IsNullOrEmpty(paramters.Scope))
            {
                List<string> scopes = GetSupportedScopes();
                if (!scopes.Contains(paramters.Scope))
                    DoRedirectUriError(Constants.OAUTH2_ERROR_INVALID_SCOPE, null, null, paramters.State);
            }
            return paramters;
        }

        public void FinishClientAuthorization(bool is_authorized)
        {
            var rp = GetAuthorizeParams();
            ResponseOAuth2Params p = new ResponseOAuth2Params();
            p.State = rp.State;
            if (!is_authorized)
            {
                p.Error = Constants.OAUTH2_ERROR_USER_DENIED;

            }
            else
            {
                if (rp.ResponseType == Constants.OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE)
                    p.AuthCode = CreateAuthCode(rp.ClientId, rp.RedirectUri, rp.Scope);

                if (rp.ResponseType == Constants.OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN)
                    p.AccessToken = CreateAccessToken(rp.ClientId, rp.Scope);
            }
            DoRedirectUriCallback(rp.RedirectUri, p);
        }
        public string GrantAccessToken()
        {
            RequestAccessTokenParams rap = new RequestAccessTokenParams();
            rap.GrantType = current.Request.QueryString[Constants.GrantTypeParameter];
            rap.Scope = current.Request.QueryString[Constants.ScopeParameter];
            rap.Code = current.Request.QueryString[Constants.CodeParameter];
            rap.RedirectUri = current.Request.QueryString[Constants.RedirectUriParameter];
            rap.Username = current.Request.QueryString[Constants.UsernameParameter];
            rap.Password = current.Request.QueryString[Constants.PasswordParameter];
            // Grant Type must be specified.
            if (string.IsNullOrEmpty(rap.GrantType))
                DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_REQUEST, null, null);

            //// Make sure we've implemented the requested grant type
            var grantTypes = GetSupportedGrantTypes();
            if (!grantTypes.Contains(rap.GrantType))
                DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE, null, null);
            //// Authorize the client
            var clientCridentials = GetClientCredentials();
            if (!CheckClientCredentials(clientCridentials.ClientId, clientCridentials.ClientSecret))
                DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_CLIENT, null, null);
            string scopes = "";
            //// Do the granting
            switch (rap.GrantType)
            {
                case Constants.OAUTH2_GRANT_TYPE_AUTH_CODE:
                    if (string.IsNullOrEmpty(rap.Code) || string.IsNullOrEmpty(rap.RedirectUri))
                        DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_REQUEST, null, null);
                    var stored = GetAuthCode(rap.Code);
                    if (stored == null)
                        DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, null, null, null);
                    scopes = stored.Scopes;
                    // Ensure that the input uri starts with the stored uri 
                    if (!rap.RedirectUri.Equals(stored.RedirectUri, StringComparison.CurrentCultureIgnoreCase))
                        DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_GRANT, null, null);

                    if (!clientCridentials.ClientId.Equals(stored.ClientId, StringComparison.CurrentCultureIgnoreCase))
                        DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_GRANT, null, null);
                    if (stored.Expires < DateTime.Now.TimeOfDay)
                        DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_EXPIRED_TOKEN, null, null);
                    break;
                case Constants.OAUTH2_GRANT_TYPE_USER_CREDENTIALS:
                    if (string.IsNullOrEmpty(rap.Username) || string.IsNullOrEmpty(rap.Password))
                        DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_REQUEST, null, null);
                    if (!CheckUserCredentials(clientCridentials.ClientId, rap.Username, rap.Password))
                        DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_GRANT, null, null);
                    break;
                default: break;
            }
            //// Check scope, if provided
            if (!string.IsNullOrEmpty(rap.Scope) && !CheckScope(scopes, rap.Scope))
                DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_SCOPE, null, null);
            string token = CreateAccessToken(clientCridentials.ClientId, rap.Scope);
            return token;
        }
        public bool VerifyAccessToken(string scope, out string error)
        {
            error = "";
            string access_token = current.Request.QueryString[Constants.AccessTokenParameter];
            // Access token was not provided
            if (string.IsNullOrEmpty(access_token))
            {
                error = "The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.";
                return false;
            }
            AuthTokenInfo token = GetAccessToken(access_token);
            if (token == null)
            {
                error = "The access token provided is invalid.";
                return false;
            }
            //// Check token expiration (I'm leaving this check separated, later we'll fill in better error messages)
            if (token.Expires < DateTime.Now.TimeOfDay)
            {
                error = "The access token provided has expired.";
                return false;
            }
            //// Check scope, if provided
            if (!string.IsNullOrEmpty(scope) && !CheckScope(token.Scopes, scope))
            {
                error = "The request requires higher privileges than provided by the access token.";
                return false;
            }
            return true;
        }
        #endregion

        #region protected
        protected virtual List<string> GetSupportedGrantTypes()
        {
            var list = new List<string>();
            list.Add(Constants.OAUTH2_GRANT_TYPE_AUTH_CODE);
            list.Add(Constants.OAUTH2_GRANT_TYPE_USER_CREDENTIALS);
            return list;
        }
        protected virtual List<string> GetSupportedAuthResponseTypes()
        {
            var list = new List<string>();
            list.Add(Constants.OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE);
            list.Add(Constants.OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN);
            return list;
        }
        protected virtual List<string> GetSupportedScopes()
        {
            var list = new List<string>();
            list.Add(Constants.OAUTH2_SCOPE_BASIC);
            return list;
        }
        protected string CreateAccessToken(string client_id, string scope)
        {
            string access_token = GenAccessToken();
            int expires_in = Constants.OAUTH2_DEFAULT_ACCESS_TOKEN_LIFETIME;
            SetAccessToken(access_token, client_id, DateTime.Now.AddMinutes(expires_in).TimeOfDay, scope);
            return string.Format("{3}access_token:\"{0}\",expires_in:\"{1}\",scope:\"{2}\"{4}", access_token, expires_in, scope, "{", "}");
        }
        protected string CreateAuthCode(string client_id, string redirect_uri, string scope)
        {
            string code = GenAuthCode();
            SetAuthCode(code, client_id, redirect_uri, DateTime.Now.AddMinutes(Constants.OAUTH2_DEFAULT_AUTH_CODE_LIFETIME).TimeOfDay, scope);
            return code;
        }
        protected string GenAccessToken()
        {
            return Guid.NewGuid().ToString();
        }
        protected string GenAuthCode()
        {
            return Guid.NewGuid().ToString();
        }
        protected ClientInfo GetClientCredentials()
        {
            ClientInfo cc = new ClientInfo();
            cc.ClientId = current.Request.QueryString[Constants.ClientIdParameter];
            cc.ClientSecret = current.Request.QueryString[Constants.ClientSecretParameter];
            if (string.IsNullOrEmpty(cc.ClientId))
                DoRedirectUriError(Constants.OAUTH2_HTTP_BAD_REQUEST, Constants.OAUTH2_ERROR_INVALID_CLIENT, null, null);
            return cc;
        }
        /// <summary>
        /// 验证客户端是否存在
        /// </summary>
        /// <param name="client_id"></param>
        /// <param name="client_secret"></param>
        /// <returns></returns>
        protected abstract bool CheckClientCredentials(string client_id, string client_secret);
        /// <summary>
        /// 获取验证通过的Code
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        protected abstract AuthCodeInfo GetAuthCode(string code);
        /// <summary>
        /// 验证客户端下,OAuth系统的用户名和密码
        /// </summary>
        /// <param name="client_id"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        protected abstract bool CheckUserCredentials(string client_id, string username, string password);
        private bool CheckScope(string required_scopes, string available_scope)
        {
            string[] scopes = required_scopes.Split(',');
            foreach (var item in scopes)
            {
                if (item.Equals(available_scope, StringComparison.CurrentCultureIgnoreCase))
                    return true;
            }
            return false;
        }
        protected abstract string GetRedirectUri(string client_id);
        protected abstract void SetAccessToken(string oauth_token, string client_id, TimeSpan expires, string scope);
        protected abstract void SetAuthCode(string code, string client_id, string redirect_uri, TimeSpan expires, string scope);
        protected abstract AuthTokenInfo GetAccessToken(string access_token);
        #endregion
        #region private

        private void DoRedirectUriCallback(string redirect_uri, ResponseOAuth2Params param)
        {
            string url = "";
            if (string.IsNullOrEmpty(param.Error))
            {
                DoRedirectUriError(param.Error, null, null, null);
            }
            if (param.ResponseType == Constants.OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE)
            {
                url = string.Format("{0}?code={1}&state={2}", redirect_uri, param.AuthCode, param.State);
            }

            if (param.ResponseType == Constants.OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN)
            {
                url = string.Format("{0}?access_token={1}&expires_in={2}&state={3}", redirect_uri, param.AccessToken, param.ExpiresIn, param.State);
            }
            current.Response.Redirect(url);
        }
        private void DoRedirectUriError(string error, string error_description, string error_uri, string state)
        {
            OAuth2Exception er = new OAuth2Exception();
            er.Error = error;
            er.ErrorDescription = error_description;
            er.ErrorUri = error_uri;
            er.State = state;
            throw er;
        }
        #endregion
    }
}