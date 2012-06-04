using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace OAuth2Server
{
    public partial class AccessToken : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Page.IsPostBack)
            {
                MSOAuth2 msOAuth2 = new MSOAuth2();
                msOAuth2.GrantAccessToken();
            }
        }
    }
}