using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.IO;
using System.Collections.Specialized;

public partial class OTP : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        try
        {
            if (Request.Form.Keys.Count > 0)
            {
                string aadhaar_no = Request.Form[0].ToString();
                Response.Write(generateotp(aadhaar_no));
                             
            }
            else
            {
                Response.Write("GET Method not allowed. Please POST required parameters as per API specification Document.");
            }
        }
        catch(Exception ex)
        {
            Response.Write(ex.Message);
        }
    }

    private string generateotp(string strAdhaar)
    {
        string strotp= "";
        Aadhaar aadhar = new Aadhaar();
        strotp = aadhar.GetOTP(strAdhaar);
        return strotp;
    }


    
}