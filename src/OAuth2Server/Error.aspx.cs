using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace OAuth2Server
{
    public partial class Error : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            Exception ex = Server.GetLastError();
            if (ex is OAuth2Exception)
            {
                var authEx = (OAuth2Exception)ex;
                lblError.Text = authEx.Error;
            }
            else
            {
                lblError.Text = ex.Message;
            }
        }
    }
}