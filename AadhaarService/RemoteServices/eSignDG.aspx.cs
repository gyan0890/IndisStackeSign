using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.IO;
using System.Collections.Specialized;
using iTextSharp.text;
using iTextSharp.text.pdf;

public partial class eSignDG : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        try
        {
            if (Request.Form.Keys.Count > 0)
            {
                string aadhaar_no = Request.Form[0].ToString();
                string otp = Request.Form[1].ToString();
                string pdfbase64req = Request.Form[2].ToString();
                string mimetype = Request.Form[3].ToString();
                string signername = Request.Form[4].ToString();
                string pdfbase64 = pdfbase64req.ToString().Replace(" ", "+");
                //Response.Write("AadharNo:" + aadhaar_no);
                //Response.Write("OTP:" + otp);
                //Response.Write("PDF:" + pdfbase64req);
                byte[] sPDFDecoded = Convert.FromBase64String(pdfbase64);
                if (mimetype == "application/pdf")
                {
                    Response.Write(signedpdf(aadhaar_no, otp, sPDFDecoded,signername));
                }
                else
                {
                    iTextSharp.text.Image image = iTextSharp.text.Image.GetInstance(sPDFDecoded);
                    float h = image.ScaledHeight;
                    float w = image.ScaledWidth;
                    float scalePercent;
                    using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
                    {
                        Rectangle defaultPageSize = PageSize.A4;
                        using (Document document = new Document(defaultPageSize))
                        {
                            PdfWriter.GetInstance(document, memoryStream);
                            document.Open();
                            float width = defaultPageSize.Width
                                  - document.RightMargin
                                  - document.LeftMargin
                                ;
                            float height = defaultPageSize.Height
                                  - document.TopMargin
                                  - document.BottomMargin
                                ;
                            if (h > w)
                            {
                                // only scale image if it's height is __greater__ than
                                // the document's height, accounting for margins
                                if (h > height)
                                {
                                    scalePercent = height / h;
                                    image.ScaleAbsolute(w * scalePercent, h * scalePercent);
                                }
                            }
                            else
                            {
                                // same for image width        
                                if (w > width)
                                {
                                    scalePercent = width / w;
                                    image.ScaleAbsolute(w * scalePercent, h * scalePercent);
                                }
                            }
                            document.Add(image);
                            document.Close();
                            byte[] bytes = memoryStream.ToArray();
                            memoryStream.Close();
                            Response.Write(signedpdf(aadhaar_no, otp, bytes,signername));
                        }
                    }
                }
                         
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
    
    private string signedpdf(string strAdhaar, string strOTP, byte[] strPDFBase64String,string signer_name)
    {
        string strSignedpdf = "";
        Aadhaar aadhar = new Aadhaar();
        byte[] fileData = null;
        fileData = strPDFBase64String;
        strSignedpdf = aadhar.eSignWithOTP(strAdhaar, strOTP, fileData,signer_name);
        return strSignedpdf;
    }


    
}