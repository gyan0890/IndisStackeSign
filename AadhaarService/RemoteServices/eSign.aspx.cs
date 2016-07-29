using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Data;
using iTextSharp.text;
using iTextSharp.text.pdf;

public partial class eSign : System.Web.UI.Page
{
   Aadhaar aadhar = new Aadhaar();
   protected void Page_Load(object sender, EventArgs e)
   {
       if (!IsPostBack)
       {
       }
   }
   protected void btnsubmit_Click(object sender, EventArgs e)
    {
        try
        {
            string pdffile = null;
            byte[] fileData = null;
            if (uploadpdf.PostedFile != null)
            {
                    HttpPostedFile myFile = uploadpdf.PostedFile;
                    using (var binaryReader = new BinaryReader(Request.Files[0].InputStream))
                    {
                        fileData = binaryReader.ReadBytes(Request.Files[0].ContentLength);
                    }
                    if (txtmimetype.Text == "application/pdf")
                    {
                        pdffile = aadhar.eSignWithOTP(txtaadhar.Text, txtotp.Text, fileData,"Puneet Kumar");
                    }
                    else
                    {
                        iTextSharp.text.Image image = iTextSharp.text.Image.GetInstance(fileData);
                        float h = image.ScaledHeight;
                        float w = image.ScaledWidth;
                        float scalePercent;
                        using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
                        {
                            Rectangle defaultPageSize = PageSize.A4;
                            using (Document document = new Document(defaultPageSize))
                            {
                                PdfWriter.GetInstance(document,memoryStream);
                                document.Open();
                                // if you don't account for the left/right margins, the image will
                                // run off the current page
                                float width = defaultPageSize.Width
                                  - document.RightMargin
                                  - document.LeftMargin
                                ;
                                float height = defaultPageSize.Height
                                  - document.TopMargin
                                  - document.BottomMargin
                                ;
                                    // scale percentage is dependent on whether the image is 
                                    // 'portrait' or 'landscape'        
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
                                    pdffile = aadhar.eSignWithOTP(txtaadhar.Text, txtotp.Text, bytes,"Puneet Kumar");
                               
                            }
                           
                        }

                    }
               
                
            }
            if (pdffile != null)
            {
                string status = "";
                string doc_Content = "";
                Dictionary<string, string> jsonresult = JsonConvert.DeserializeObject<Dictionary<string, string>> (pdffile);
				status = jsonresult ["status"];
				doc_Content=jsonresult ["doc_content"];
				if (status == "True")
                {
                   Literal1.Text = "<iframe src=\"data:application/pdf;base64," + doc_Content + "\" style='width:95%; height:1000px;'></iframe>";
                }
                else
                {
                   Literal1.Text = "<p style='font-size:20px; color:red; font-weight:bold;'>No pdf generated.</p>";
                }
               
            }
            
        }
        catch(Exception ex)
        {
            Literal1.Text = ex.Message;
        }

    }
   protected void btngenerateotp_Click(object sender, EventArgs e)
   {
       try
       {
               string otpmessage = "";
               if (txtaadhar.Text != null && txtaadhar.Text != "")
               {
                   otpmessage = aadhar.GetOTP(txtaadhar.Text);
               }
               else
               {
                   EmptyAadharPanel.CssClass = "show";
               }
              if (!string.IsNullOrEmpty(otpmessage))
               {
                   string status = "";
                   string msg = "";
                   Dictionary<string, string> jsonresult = JsonConvert.DeserializeObject<Dictionary<string, string>>(otpmessage);
                   status = jsonresult["status"];
                   msg = jsonresult["msg"];
                   if (status == "True")
                   {
                       SuccessMessagePanel.CssClass = "show";
                   }
                   else
                   {
                       FailMessagePanel.CssClass = "show";
                   }

               }
                       
       }
       catch (Exception ex)
       {
       }
   }
}