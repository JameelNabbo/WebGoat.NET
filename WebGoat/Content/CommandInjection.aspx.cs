using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace OWASP.WebGoat.NET
{
    public partial class CommandInjection : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            String Password = "123456";
        }
    }
}
