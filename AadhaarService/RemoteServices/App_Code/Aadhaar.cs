using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Services;
using AllAuthClass;
using System.Xml;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.IO;
using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using iTextSharp.text.pdf;

/// <summary>
/// Summary description for Aadhaar
/// </summary>
[WebService(Namespace = "http://tempuri.org/")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]

public class Aadhaar : System.Web.Services.WebService {
    Commonfun objCommonfun = new Commonfun();
    #region variables
    public string ASPID { get; set; }
    public string PFXPath { get; set; }
    public string PFXPassword { get; set; }
    public string eSignURL { get; set; }
    public string OTPURL { get; set; }
    public string AadharNumber { get; set; }
    public string OTP { get; set; }
    public string SIGNATUREREASON { get; set; }
    public string CITY { get; set; }
    public string CERTLOCATION { get; set; }
    public int SIGNPAGENO { get; set; }
    public string UIDAI_cer { get; set; }

    private string timeStamp;
    private string transactionID;
    private string responseXML;
    private string requestXML;
    #endregion
    [WebMethod]
    public string GetOTP(string AadharNo)
    {
        string result = "";
        string json = "";
        if (AadharNo == "")
        {
            json = "";
            json += "{";
            json += "\"status\":false";
            json += ",\"msg\":\"Enter AAdhar !\"";
            json += "}";
            result = json;

        }
        else
        {
            if (objCommonfun.isValidAadhaar(AadharNo))
            {
                AuthOTP objAuthOTP = new AuthOTP();
                StringBuilder strotp = new StringBuilder();
                ASPID = System.Configuration.ConfigurationManager.AppSettings["ASPID"].ToString();
                transactionID = DateTime.Now.ToString("yyyyMMddThhmmss");
                timeStamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");
                strotp.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                strotp.Append("<OTP ver=\"1.0\" aspId=\"" + ASPID + "\" ts=\"" + timeStamp + "\" uid=\"" + AadharNo + "\" txn=\"" + transactionID + "\">");
                strotp.Append("</OTP>");
                requestXML = strotp.ToString();
                PFXPath = System.Web.HttpContext.Current.Server.MapPath(System.Configuration.ConfigurationManager.AppSettings["ClientCertificate"].ToString());
                PFXPassword = "emudhra";
                if (!string.IsNullOrEmpty(PFXPath))
                {
                    requestXML = SignXML(requestXML);

                }
                eSignURL = objCommonfun.getHttpOTPRequesturl();
                string URL = eSignURL;
                if (!string.IsNullOrEmpty(URL) && !string.IsNullOrEmpty(requestXML))
                {
                    responseXML = HttpsWebClientSendSMS(URL, System.Web.HttpUtility.UrlEncode(requestXML));
                    var xml = new XmlDocument();
                    xml.LoadXml(responseXML);
                    XmlNode OTPResp = xml.SelectSingleNode("OTPResp");
                    if (OTPResp.Attributes["errCode"].Value != string.Empty)
                    {
                        json = "";
                        json += "{";
                        json += "\"status\":false";
                        json += ",\"msg\":\"" + OTPResp.Attributes["errMsg"].Value + "\"";
                        json += "}";
                        result = json;
                    }
                    else if (OTPResp.Attributes["status"].Value != "0")
                    {
                        json = "";
                        json += "{";
                        json += "\"status\":true";
                        json += ",\"msg\":\"OTP generated successfully\"";
                        json += "}";
                        result = json;
                    }
                    else
                    {
                        json = "";
                        json += "{";
                        json += "\"status\":false";
                        json += ",\"msg\":\"OTP generation failed\"";
                        json += "}";
                        result = json;
                    }
                }
           }
            else
            {
                json = "";
                json += "{";
                json += "\"status\":false";
                json += ",\"msg\":\"Invalid Aadhar !\"";
                json += "}";
                result = json;
            }
        }
        return result;
    }

    [WebMethod]
    public string[] KYCData(string AadhaarNo, string otp)
    {
        List<string> stringList = new List<string>();

        if (AadhaarNo == "")
        {            
            stringList.Add("Enter AAdhar !");
        }
        else
        {

            if (otp.Trim() == "")
            {
                stringList.Add("Enter OTP!");

            }
            else
            {
                if (objCommonfun.isValidAadhaar(AadhaarNo))
                {
                    stringList.Add("Success.");


                    # region KYC
                    string ts = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");

                    AuthKYC_OTP objAuthOTP = new AuthKYC_OTP();


                    string pid = objAuthOTP.GenPIDXML_KYC_OTP(otp.Trim(), ts);
                    string publicKey = objCommonfun.readFicate();
                    string AuthXmlToSend = objAuthOTP.GenAuthXML_KYC_OTP(AadhaarNo, publicKey, pid);
                    string kycXmlToSend = objAuthOTP.GenKycXML(AuthXmlToSend, ts);
                    string esignXmlToSend = objAuthOTP.GeneSignXML(kycXmlToSend, ts);

                    string ResponseXML = "";
                    string HttpWebRequesturl = objCommonfun.getHttpWebRequesturl();
                    string Urlencoded = HttpUtility.UrlEncode(HttpWebRequesturl);
                    ResponseXML = objCommonfun.Postauthxml_OnAUA(esignXmlToSend, Urlencoded);


                    string output = objCommonfun.ParseRespXML(ResponseXML);

                    XmlDocument Doc = new XmlDocument();
                    Doc.LoadXml(ResponseXML);

                    XmlNode POI = Doc.SelectSingleNode("/KycRes/UidData/Poi");

                    if (!(POI.SelectSingleNode("@name") == null))
                        stringList.Add(POI.SelectSingleNode("@name").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POI.SelectSingleNode("@dob") == null))
                        stringList.Add(POI.SelectSingleNode("@dob").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POI.SelectSingleNode("@gender") == null))
                        stringList.Add(POI.SelectSingleNode("@gender").Value.ToString());
                    else
                        stringList.Add("NA");

                    
                    if (!(POI.SelectSingleNode("@email") == null))
                        stringList.Add(POI.SelectSingleNode("@email").Value.ToString());
                    else
                        stringList.Add("NA");


                    if (!(POI.SelectSingleNode("@phone") == null))
                        stringList.Add(POI.SelectSingleNode("@phone").Value.ToString());
                    else
                        stringList.Add("NA");

                    
                    XmlNode POA = Doc.SelectSingleNode("/KycRes/UidData/Poa");


                    if (!(POA.SelectSingleNode("@co") == null))
                        stringList.Add(POA.SelectSingleNode("@co").Value.ToString());
                    else
                        stringList.Add("NA");
                    
               
                    if (!(POA.SelectSingleNode("@house") == null))
                        stringList.Add(POA.SelectSingleNode("@house").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POA.SelectSingleNode("@street") == null))
                    stringList.Add(POA.SelectSingleNode("@street").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POA.SelectSingleNode("@vtc") == null))
                        stringList.Add(POA.SelectSingleNode("@vtc").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POA.SelectSingleNode("@po") == null))
                        stringList.Add(POA.SelectSingleNode("@po").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POA.SelectSingleNode("@subdist") == null))
                        stringList.Add(POA.SelectSingleNode("@subdist").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POA.SelectSingleNode("@dist") == null))
                        stringList.Add(POA.SelectSingleNode("@dist").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POA.SelectSingleNode("@state") == null))
                        stringList.Add(POA.SelectSingleNode("@state").Value.ToString());
                    else
                        stringList.Add("NA");

                    if (!(POA.SelectSingleNode("@pc") == null))
                       stringList.Add(POA.SelectSingleNode("@pc").Value.ToString());
                    else
                        stringList.Add("NA");
                    
                    
                    XmlNode Pht = Doc.SelectSingleNode("/KycRes/UidData/Pht");

                    if (!(Pht == null))
                        stringList.Add(Pht.InnerText.ToString());
                    else
                        stringList.Add("NA");
                    
                    

                    #endregion

                }
                else
                {
                    stringList.Add("Invalid Aadhaar!");

                }
            }
        }

        return stringList.ToArray();

        
    }
    private void SetAttribute(XmlDocument XD, XmlNode XN, string AttName, string AttValue)
    {
        XmlAttribute Att = XN.Attributes.Append(XD.CreateAttribute(AttName));
        Att.InnerText = AttValue;
    }
    public string getHttpWebRequesturl()
    {
        return System.Configuration.ConfigurationManager.AppSettings["ServiceURL"].ToString();
    }
    [WebMethod]
    public string eSignWithOTP(string aadhar_no, string otp, byte[] PDFdocument, string SignerName)
    {
            string result = "";
            string json = "";
            OTP = otp;
            string newFileName = System.Web.HttpContext.Current.Server.MapPath(System.Configuration.ConfigurationManager.AppSettings["LogFile"].ToString());
            ASPID = System.Configuration.ConfigurationManager.AppSettings["ASPID"].ToString();
            //ASPID = "ASPDIETY";
            AadharNumber = aadhar_no;
            PdfSignatureAppearance appearance = null;
            iTextSharp.text.Rectangle rect = null;
            DateTime dttxn = DateTime.Now;
            StringBuilder straddhar = new StringBuilder();
            PdfReader reader;
            PdfStamper stamper;
            SIGNATUREREASON = System.Configuration.ConfigurationManager.AppSettings["SIGNATUREREASON"].ToString();
            CITY = System.Configuration.ConfigurationManager.AppSettings["CITY"].ToString();
            SIGNPAGENO = 1;
            CERTLOCATION = System.Configuration.ConfigurationManager.AppSettings["CERTLOCATION"].ToString();
            transactionID = DateTime.Now.ToString("yyyyMMddThhmmss");
            timeStamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");
            string TempFile = string.Empty;
            int PdfPagenumber = 0;
         
            ArrayList TempFiles;
            byte[] sigbytes = null, paddedSig = null, TemposBytes = null;
            string PDFPassword = "1234";
            if (!string.IsNullOrEmpty(PDFPassword))
                reader = new PdfReader(PDFdocument, new ASCIIEncoding().GetBytes(PDFPassword));
            else
                reader = new PdfReader(PDFdocument);
            PdfReader.unethicalreading = true;
            PdfPagenumber = reader.NumberOfPages;
            TempFiles = new ArrayList();
            MemoryStream os = null;
            PdfDictionary dic2 = null;
            for (int i = 1; i <= PdfPagenumber; i++)
            {
                if (i != 1)
                {
                    if (!string.IsNullOrEmpty(PDFPassword))
                        reader = new PdfReader(TemposBytes, new ASCIIEncoding().GetBytes(PDFPassword));
                    else
                        reader = new PdfReader(TemposBytes);
                    PdfReader.unethicalreading = true;
                    if(os==null)
                    os = new MemoryStream();
                }
                else
                {
                    if (os == null)
                    os = new MemoryStream();
                }

                if (i == SIGNPAGENO)
                {
                    stamper = PdfStamper.CreateSignature(reader, os, '\0', null, true);
                    appearance = stamper.SignatureAppearance;
                    //appearance.Reason = SIGNATUREREASON;
                    //appearance.Layer2Text = "Reason:" + SIGNATUREREASON + "\n" + "Date:" + DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss");
                    appearance.Layer2Text = "Signed by: " + SignerName + "\n" + "using " + SIGNATUREREASON + "\n" + "Date: " + DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss");
                    // appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION;
                    //appearance.Location = CITY;
                    //appearance.SignDate = DateTime.Parse(DateTime.Now.ToString("dd-MM-yyyy hh:mm:ss"));
                    appearance.Acro6Layers = false;
                    appearance.Image = null;
                    List<iTextSharp.text.Rectangle> rList = new List<iTextSharp.text.Rectangle>();
                    string[] Cordinatespagelevel = CERTLOCATION.Split(';');
                    string[] Pagelevel;
                    int[] pages = new int[Cordinatespagelevel.Length];
                    for (int j = 0; j < Cordinatespagelevel.Length; j++)
                    {
                        Pagelevel = Cordinatespagelevel[j].Split(',');
                        if (Pagelevel.Length > 1)
                        {
                            pages[j] = Convert.ToInt32(Pagelevel[0]);
                            rect = new iTextSharp.text.Rectangle(Convert.ToInt32(Pagelevel[0]), Convert.ToInt32(Pagelevel[1]), Convert.ToInt32(Pagelevel[2]), Convert.ToInt32(Pagelevel[3]));
                            rList.Add(rect);
                        }
                    }
                    appearance.SetVisibleSignature(rect, i, null);
                }
                if (i == 1)
                {
                int contentEstimated = 8192;
                Dictionary<PdfName, int> exc = new Dictionary<PdfName, int>();
                exc[PdfName.CONTENTS] = contentEstimated * 2 + 2;
                PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
                //dic.Reason = appearance.Reason;
                // dic.Date = new PdfDate(appearance.SignDate);
                appearance.CryptoDictionary = dic;
                appearance.PreClose(exc);
                  Stream ostr = appearance.GetRangeStream();
                    HashAlgorithm sha = new SHA256CryptoServiceProvider();
                    int read = 0;
                    byte[] buff = new byte[contentEstimated];
                    while ((read = ostr.Read(buff, 0, contentEstimated)) > 0)
                    {
                        sha.TransformBlock(buff, 0, read, buff, 0);
                    }
                    sha.TransformFinalBlock(buff, 0, 0);
                    byte[] hashd = Org.BouncyCastle.Utilities.Encoders.Hex.Encode(sha.Hash);

                    //eSign Start
                   
                    string hashdocument = Encoding.UTF8.GetString(hashd, 0, hashd.Length);
                    string AADHARXML = GetAadhaarXML();
                    string BASE64AadhaarXML = Convert.ToBase64String(new System.Text.ASCIIEncoding().GetBytes(AADHARXML));
                    straddhar.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                    straddhar.Append("<Esign ver=\"1.0\" sc=\"Y\" aspId=\"" + ASPID + "\" esignClass=\"" + "1" + "\" preferredCa=\"" + "emudra" + "\" ts=\"" + timeStamp + "\" txn=\"" + transactionID + "\">");
                    straddhar.Append("<Input>" + hashdocument + "</Input>");
                    straddhar.Append("<Aadhaar>" + BASE64AadhaarXML + "</Aadhaar>");
                    straddhar.Append("</Esign>");
                    requestXML = straddhar.ToString();
                    PFXPath = System.Web.HttpContext.Current.Server.MapPath(System.Configuration.ConfigurationManager.AppSettings["ClientCertificate"].ToString());
                    PFXPassword = "emudhra";
                    if (!string.IsNullOrEmpty(PFXPath))
                    {
                       requestXML = SignXML(requestXML);
                    }
                   eSignURL = objCommonfun.getHttpWebRequesturl();
                   string URL = eSignURL;
                   if (!string.IsNullOrEmpty(URL) && !string.IsNullOrEmpty(requestXML))
                        {
                           responseXML = HttpsWebClientSendSMS(URL, System.Web.HttpUtility.UrlEncode(requestXML));
                           var xml = new XmlDocument();
                            xml.LoadXml(responseXML);
                            XmlNode EsignResp = xml.SelectSingleNode("EsignResp");
                            if (EsignResp.Attributes["errCode"].Value != string.Empty)
                            {
                                json = "";
                                json += "{";
                                json += "\"status\":false";
                                json += ",\"doc_content\":\"\"";
                                json += ",\"msg\":\"" +  EsignResp.Attributes["errMsg"].Value + "\"";
                                json += "}";
                                result = json;
                                string clientDetails = aadhar_no + "," + otp + "," + "false" + "," + EsignResp.Attributes["errMsg"].Value + "," + DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss") + Environment.NewLine;
                                //if (!File.Exists(newFileName))
                                //{
                                //    string clientHeader = "Aadhaar Number" + "," + "OTP" + "," + "Status" + "," + "Message" + "," + "Date/Time" + Environment.NewLine;

                                //    File.WriteAllText(newFileName, clientHeader);
                                //}
                                File.AppendAllText(newFileName, clientDetails);
                                return result;
                            }
                            sigbytes = SignDocument(responseXML.ToString(), PDFdocument);
                            paddedSig = new byte[contentEstimated];
                            Array.Copy(sigbytes, 0, paddedSig, 0, sigbytes.Length);
                            dic2 = new PdfDictionary();
                            dic2.Put(PdfName.CONTENTS, new PdfString(paddedSig).SetHexWriting(true));
                            appearance.Close(dic2);
                            TemposBytes = os.ToArray();
                        }
                  
                }
                else
                {
                   
                    //dic2 = new PdfDictionary();
                    dic2.Put(PdfName.CONTENTS, new PdfString(paddedSig).SetHexWriting(true));
                    //appearance.Close(dic2);
                    TemposBytes = os.ToArray();
                }
            }
            //appearance.Close(dic2);
            if (os != null)
            {
                string strSignedpdf = Convert.ToBase64String(os.ToArray());
                json = "";
                json += "{";
                json += "\"status\":true";
                json += ",\"doc_content\":\"" + strSignedpdf + "\"";
                json += ",\"msg\":\"Signed PDF generated\"";
                json += "}";
                result = json;
                string clientDetails = aadhar_no + "," + otp + "," + "true" + "," + "Signed PDF generated" + "," + DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss") + Environment.NewLine;
                //if (!File.Exists(newFileName))
                //{
                //    string clientHeader = "Aadhaar Number" + "," + "OTP" + "," + "Status" + "," + "Message" + "," + "Date/Time" + Environment.NewLine;

                //    File.WriteAllText(newFileName, clientHeader);
                //}
                File.AppendAllText(newFileName, clientDetails);
            }
            else
            {
                json = "";
                json += "{";
                json += "\"status\":false";
                json += ",\"doc_content\":\"\"";
                json += ",\"msg\":\"PDF generation failed\"";
                json += "}";
                result = json;
                string clientDetails = aadhar_no + "," + otp + "," + "false" + "," + "PDF generation failed" + "," + DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss") + Environment.NewLine;
                //if (!File.Exists(newFileName))
                //{
                //    string clientHeader = "Aadhaar Number" + "," + "OTP" + "," + "Status" + "," + "Message" + "," + "Date/Time" + Environment.NewLine;

                //    File.WriteAllText(newFileName, clientHeader);
                //}
                File.AppendAllText(newFileName, clientDetails);
            }
          return result;
        
    }
    private string GetAadhaarXML()
    {
        string PIDXML = GetPIDXML();
        StringBuilder aadhaar = new StringBuilder();
        byte[] SessionKey = getNewSessionKey();
        string Base64UIDAIPublicKeyEncryption = encryptWithPublicKey(SessionKey);
        string BASE64SessionKeyAesEncrytionPkcs7Ecb = Convert.ToBase64String(EncryptDataAES(new System.Text.ASCIIEncoding().GetBytes(PIDXML), SessionKey));
        string Base64SessionKeyAesEncrytionPkcs7EcbSHA256Hash = Convert.ToBase64String(EncryptDataAES(Generatehash256(PIDXML), SessionKey));

        aadhaar.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        aadhaar.Append("<Auth xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request/1.0\" uid=\"" + AadharNumber + "\" tid=\"public\" ver=\"1.6\" >");
        aadhaar.Append("<Meta fdc=\"NC\" idc=\"NA\" lot=\"P\" lov=\"560103\" pip=\"NA\" udc=\"UIDAI:Device:1\"/>");
        aadhaar.Append("<Skey ci=\"" + System.Configuration.ConfigurationManager.AppSettings["CertificateDate"].ToString() + "\">" + Base64UIDAIPublicKeyEncryption + "</Skey>");
        aadhaar.Append("<Data type=\"X\">" + BASE64SessionKeyAesEncrytionPkcs7Ecb + "</Data>");
        aadhaar.Append("<Hmac>" + Base64SessionKeyAesEncrytionPkcs7EcbSHA256Hash + "</Hmac>");
        aadhaar.Append("</Auth>");
        return aadhaar.ToString();
    }
            
    private string encryptWithPublicKey(byte[] stringToEncrypt)
    {
        String UIDAICertData = objCommonfun.readFicate();
        //UIDAICertData = UIDAICertData.Replace("-----BEGIN CERTIFICATE-----", string.Empty).Replace("-----END CERTIFICATE-----", string.Empty);
        byte[] CertData = Convert.FromBase64String(UIDAICertData);
        X509Certificate2 certificate = new X509Certificate2(CertData);
        byte[] cipherbytes = Convert.FromBase64String(Convert.ToBase64String(stringToEncrypt));
        RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)certificate.PublicKey.Key;
        byte[] cipher = rsa.Encrypt(cipherbytes, false);
        return Convert.ToBase64String(cipher);
    }

    private string GetPIDXML()
    {
        StringBuilder pidxml = new StringBuilder();
        pidxml.Append("<Pid xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0\" ts=\"" + timeStamp + "\" ver=\"1.0\">");
        pidxml.Append("<Pv otp=\"" + OTP + "\"/>");
        pidxml.Append("</Pid>");
        return pidxml.ToString();
    }

    private byte[] getNewSessionKey()
    {
        using (Rijndael myAes = RijndaelManaged.Create("Rijndael"))
        {
            myAes.KeySize = 256;
            myAes.GenerateKey();
            return myAes.Key;
        }
    }

    private byte[] SignDocument(string Response, byte[] PDFdocument)
    {
        String SignedXMLfile = string.Empty;
        XmlDocument responseXML = new XmlDocument();
        if (!string.IsNullOrEmpty(Response))
        {
            responseXML.LoadXml(Response.Trim());
        }
        XmlNode Usercertificate = responseXML.SelectSingleNode("//UserX509Certificate");
        String userCertificate = string.Empty;

        if (Usercertificate != null)
            userCertificate = Usercertificate.InnerText;

        if (!string.IsNullOrEmpty(userCertificate))
        {
            X509Certificate2 certificate = new X509Certificate2();
            certificate.Import(new System.Text.ASCIIEncoding().GetBytes(userCertificate));
            //this.SignerName = certificate.GetNameInfo(X509NameType.SimpleName, false);
            XmlNode Signedhash = responseXML.SelectSingleNode("//Pkcs7Response");
            String signedHash = Signedhash.InnerText;

            X509Certificate2 SignedPkcs7certificate = new X509Certificate2();
            SignedPkcs7certificate.Import(Org.BouncyCastle.Utilities.Encoders.Base64.Decode(signedHash));
            return Org.BouncyCastle.Utilities.Encoders.Base64.Decode(signedHash);
        }
        return null;
    }

    private static String HttpsWebClientSendSMS(string URI, string queryString)
    {
        string result = string.Empty;
        WebClient webclient = null;
        webclient = new WebClient();
        webclient.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
        result = webclient.UploadString(URI, queryString);
        return (result);
    }
    private String SignXML(String XMLValue)
    {
       try
        {
            
            string SignedXML = string.Empty;
            X509Certificate2 Cert = new System.Security.Cryptography.X509Certificates.X509Certificate2();
           
            CryptoConfig.AddAlgorithm(typeof(System.Security.Cryptography.SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
           
            Cert = new X509Certificate2(PFXPath, PFXPassword,X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            
                XmlDocument Document = new XmlDocument();
                Document.LoadXml(XMLValue);
               
                // Export private key from cert.PrivateKey and import into a PROV_RSA_AES provider:
                var exportedKeyMaterial = Cert.PrivateKey.ToXmlString( /* includePrivateParameters = */ true);
                var key = new RSACryptoServiceProvider();
                key.PersistKeyInCsp = false;
                key.FromXmlString(exportedKeyMaterial);
               
                SignedXml signedXml = new SignedXml(Document);
               
                signedXml.SigningKey = key;
               
                // Add a signing reference, the uri is empty and so the whole document 
                // is signed. 
                Reference reference = new Reference();
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.Uri = "";
                signedXml.AddReference(reference);
                
                // Add the certificate as key info, because of this the certificate 
                // with the public key will be added in the signature part. 
                KeyInfo keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(Cert));
                signedXml.KeyInfo = keyInfo;
               
                // Generate the signature. 
                signedXml.ComputeSignature();

                // Get the XML representation of the signature and save 
                // it to an XmlElement object.
                XmlElement xmlDigitalSignature = signedXml.GetXml();
               
                Document.DocumentElement.AppendChild(
                Document.ImportNode(xmlDigitalSignature, true));
               
                SignedXML = Document.OuterXml;
               
                return SignedXML;
           
        }
        catch(Exception ex)
        {
            return null;
        }
    }
   
    private static byte[] EncryptDataAES(byte[] toEncrypt, byte[] key)
    {
        IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/PKCS7");
        byte[] iv = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                                                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                                                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                                                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

        cipher.Init(true, new KeyParameter(key));

        int outputSize = cipher.GetOutputSize(toEncrypt.Length);
        byte[] tempOP = new byte[outputSize];
        int processLen = cipher.ProcessBytes(toEncrypt, 0, toEncrypt.Length, tempOP, 0);
        int outputLen = cipher.DoFinal(tempOP, processLen);

        byte[] result = new byte[processLen + outputLen];
        System.Array.Copy(tempOP, 0, result, 0, result.Length);
        return result;
    }

    private static byte[] Generatehash256(string text)
    {
        byte[] message = Encoding.UTF8.GetBytes(text);

        UnicodeEncoding UE = new UnicodeEncoding();
        byte[] hashValue;
        SHA256Managed hashString = new SHA256Managed();
        hashValue = hashString.ComputeHash(message);
        return hashValue;
    }
//public byte[] eSign(string AADHAR, string OTP, byte[] pdfdoc)
//    public string eSign(string AADHAR, string OTP, byte[] pdfdoc)
//    {
//        try 
//        {
//           //byte[] esignepdf = eSignWithOTP(AADHAR,OTP,pdfdoc);
//           string esignepdf = eSignWithOTP(AADHAR, OTP, pdfdoc);
//           if (esignepdf != null)
//            {
//                    //e_signEntities entities = new e_signEntities();
//                    //t_esign_log addrecord = new t_esign_log();
//                    //addrecord.aadhaar_no = AADHAR;
//                    //addrecord.otp = OTP;
//                    //addrecord.pdf_doc = pdfdoc;
//                    //addrecord.transcation_id = DateTime.Now.ToString("yyyyMMddThhmmss");
//                    //addrecord.status = "Success";
//                    //entities.AddTot_esign_log(addrecord);
//                    //entities.SaveChanges();
//                return esignepdf;
//            }
//            else
//            {
//                //e_signEntities entities = new e_signEntities();
//                //t_esign_log addrecord = new t_esign_log();
//                //addrecord.aadhaar_no = AADHAR;
//                //addrecord.otp = OTP;
//                //addrecord.pdf_doc = pdfdoc;
//                //addrecord.transcation_id = DateTime.Now.ToString("yyyyMMddThhmmss");
//                //addrecord.status = "Failed";
//                //entities.AddTot_esign_log(addrecord);
//                //entities.SaveChanges();
//                return "response is null from esign";
//            }

//        }
//        catch(Exception ex)
//        {
//            //e_signEntities entities = new e_signEntities();
//            //t_esign_log addrecord = new t_esign_log();
//            //addrecord.aadhaar_no = AADHAR;
//            //addrecord.otp = OTP;
//            //addrecord.pdf_doc = pdfdoc;
//            //addrecord.transcation_id = DateTime.Now.ToString("yyyyMMddThhmmss");
//            //addrecord.status = "Failed";
//            //entities.AddTot_esign_log(addrecord);
//            //entities.SaveChanges();
//            return ex.Message;

//        }

//}

}
