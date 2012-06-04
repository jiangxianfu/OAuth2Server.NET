using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Runtime.Serialization;

namespace OAuth2Server
{
    public class OAuth2Exception : Exception
    {
        public OAuth2Exception()
        {
        }
        public OAuth2Exception(string message)
            : base(message)
        {
            Error = message;
        }
        public string ErrorUri { get; set; }
        public string State { get; set; }
        public string Error { get; set; }
        public string ErrorDescription { get; set; }
    }
}