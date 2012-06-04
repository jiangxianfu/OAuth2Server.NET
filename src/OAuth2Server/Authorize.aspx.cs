using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace OAuth2Server
{
    public partial class Authorize : System.Web.UI.Page
    {
        MSOAuth2 msOauth2 = new MSOAuth2();
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Page.IsPostBack)
            {
                var OauthRequestParam = msOauth2.GetAuthorizeParams();
            }
        }

        protected void btnLogin_Click(object sender, EventArgs e)
        {
            //检查用户名和密码

            msOauth2.FinishClientAuthorization(true);
        }
    }
}