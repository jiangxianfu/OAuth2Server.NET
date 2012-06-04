using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OAuth2Server
{
    public class Constants
    {
        public const int OAUTH2_DEFAULT_ACCESS_TOKEN_LIFETIME = 3600;
        public const int OAUTH2_DEFAULT_AUTH_CODE_LIFETIME = 30;
        //public const int OAUTH2_DEFAULT_REFRESH_TOKEN_LIFETIME = 1209600;
        //public const string OAUTH2_CLIENT_ID_REGEXP = "/^[a-z0-9-_]{3,32}$/i";

        public const string OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN = "token";
        public const string OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE = "code";
        //public const string OAUTH2_AUTH_RESPONSE_TYPE_CODE_AND_TOKEN = "code-and-token";
        //public const string OAUTH2_AUTH_RESPONSE_TYPE_REGEXP = "/^(token|code|code-and-token)$/";
        //public const string OAUTH2_AUTH_RESPONSE_TYPE_REGEXP = "/^(token|code)$/";

        public const string OAUTH2_GRANT_TYPE_AUTH_CODE = "authorization_code";
        public const string OAUTH2_GRANT_TYPE_USER_CREDENTIALS = "password";
        //public const string OAUTH2_GRANT_TYPE_ASSERTION = "assertion";
        //public const string OAUTH2_GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
        //public const string OAUTH2_GRANT_TYPE_NONE = "none";
        //public const string OAUTH2_GRANT_TYPE_REGEXP = "/^(authorization_code|password)$/";


        public const string OAUTH2_SCOPE_BASIC = "basic";

        

        public const string OAUTH2_HTTP_FOUND = "302 Found";
        public const string OAUTH2_HTTP_BAD_REQUEST = "400 Bad Request";
        //public const string OAUTH2_HTTP_UNAUTHORIZED = "401 Unauthorized";
        //public const string OAUTH2_HTTP_FORBIDDEN = "403 Forbidden";

        public const string OAUTH2_ERROR_INVALID_REQUEST = "invalid_request";
        public const string OAUTH2_ERROR_INVALID_CLIENT = "invalid_client";
        //public const string OAUTH2_ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client";
        public const string OAUTH2_ERROR_REDIRECT_URI_MISMATCH = "redirect_uri_mismatch";
        public const string OAUTH2_ERROR_USER_DENIED = "access_denied";
        public const string OAUTH2_ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
        public const string OAUTH2_ERROR_INVALID_SCOPE = "invalid_scope";
        public const string OAUTH2_ERROR_INVALID_GRANT = "invalid_grant";
        public const string OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
        //public const string OAUTH2_ERROR_INVALID_TOKEN = "invalid_token";
        public const string OAUTH2_ERROR_EXPIRED_TOKEN = "expired_token";
        //public const string OAUTH2_ERROR_INSUFFICIENT_SCOPE = "insufficient_scope";

        public const string AccessTokenParameter = "access_token";
        public const string ClientIdParameter = "client_id";
        public const string ClientSecretParameter = "client_secret";
        public const string ResponseTypeParameter = "response_type";
        public const string RedirectUriParameter = "redirect_uri";
        public const string StateParameter = "state";
        public const string ScopeParameter = "scope";
        public const string GrantTypeParameter = "grant_type";
        public const string UsernameParameter = "username";
        public const string PasswordParameter = "password";
        public const string CodeParameter = "code";
    }
}