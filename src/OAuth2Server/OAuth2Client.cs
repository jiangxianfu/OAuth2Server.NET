using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Net;
using System.IO;

namespace OAuth2Server
{
    public class OAuth2Client
    {
        //申请应用时分配的AppKey
        public static readonly string client_id = "";
        //申请应用时分配的AppSecret
        public static readonly string client_secret = "";
        public static readonly string redirect_uri = "";
        public string authorizeurl()
        {
            string response_type = "code";
            return string.Format("https://api.t.sina.com.cn/oauth2/authorize?client_id={0}&&response_type={1}&redirect_uri={2}", client_id, response_type, HttpUtility.UrlEncode(redirect_uri));
        }
        /// <summary>
        /// 请求用户授权Token 
        /// </summary>
        /// <param name="redirect_uri"></param>
        /// <returns>
        /// code  string  用于调用access_token，接口获取授权后的access token。  
        /// state  string  如果传递参数，会回传该参数。 
        /// </returns>
        public string authorize()
        {
            return HttpReq.Get(authorizeurl());
        }
        /// <summary>
        /// 获取授权过的Access Token 
        /// </summary>
        /// <returns>
        /// access_token  string  用于调用access_token，接口获取授权后的access token。  
        /// expires_in  string  access_token的生命周期。  
        /// remind_in  string  access_token的剩余时间。  
        /// uid  string  当前授权用户的UID。  
        /// </returns>
        public string access_token(string code)
        {
            //请求的类型，可以为authorization_code、password、refresh_token。 
            string grant_type = "authorization_code";
            //https://api.weibo.com/oauth2/access_token 
            string url = "https://api.weibo.com/oauth2/access_token";
            string data = string.Format("client_id={0}&client_secret={1}&grant_type={2}&code={3}&redirect_uri={4}", client_id, client_secret, grant_type, code, HttpUtility.UrlEncode(redirect_uri));
            return HttpReq.Post(url, data);
        }
    }
    public class HttpReq
    {
        private static string GetHttpWebResponse(WebRequest webRequest)
        {
            StreamReader responseReader = null;
            string responseData;
            try
            {
                responseReader = new StreamReader(webRequest.GetResponse().GetResponseStream());
                responseData = responseReader.ReadToEnd();
            }
            finally
            {
                webRequest.GetResponse().GetResponseStream().Close();
                responseReader.Close();
            }

            return responseData;
        }
        private static string GetHttpWebResponse(WebRequest httpWebRequest, string postData)
        {
            var requestWriter = new StreamWriter(httpWebRequest.GetRequestStream());
            try
            {
                requestWriter.Write(postData);
            }
            finally
            {
                requestWriter.Close();
            }
            return GetHttpWebResponse(httpWebRequest);
        }
        public static string Post(string url, string postData)
        {
            var httpWebRequest = System.Net.WebRequest.Create(url) as HttpWebRequest;
            httpWebRequest.Method = "POST";
            httpWebRequest.ServicePoint.Expect100Continue = false;
            httpWebRequest.ContentType = "application/x-www-form-urlencoded";
            return GetHttpWebResponse(httpWebRequest, postData);
        }
        public static string Get(string url)
        {
            var httpWebRequest = System.Net.WebRequest.Create(url) as HttpWebRequest;
            httpWebRequest.Method = "GET";
            httpWebRequest.ServicePoint.Expect100Continue = false;
            return GetHttpWebResponse(httpWebRequest);
        }
    }
}