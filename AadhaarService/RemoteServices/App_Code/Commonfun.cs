using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Xml;

namespace AllAuthClass
{
    public class Commonfun
    {
        public Commonfun()
        {
            //
            // TODO: Add constructor logic here
            //
        }
        public Boolean isNumericAadhaar(string aadhaar)
        {
            System.Text.RegularExpressions.Regex expr;
            expr = new Regex(@"^\d{12}$");
            if (expr.IsMatch(aadhaar))
            {
                return true;
            }
            else return false;
        }


        public Boolean isValidAadhaar(string aadhaar)
        {
            if (aadhaar.Length == 12)
            {
                if (isNumericAadhaar(aadhaar))
                {
                    if (Verhoeff.validateVerhoeff(aadhaar))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public string getHttpWebRequesturl()
        {
            return System.Configuration.ConfigurationManager.AppSettings["ServiceURL"].ToString();
        }

        public string getHttpOTPRequesturl()
        {
            return System.Configuration.ConfigurationManager.AppSettings["OTPURL"].ToString();
        }
        public string readFicate()
        {

            // Read The the certificate  from path
            WebClient client = new WebClient();
            Stream stream = client.OpenRead(System.Web.HttpContext.Current.Server.MapPath(System.Configuration.ConfigurationManager.AppSettings["Certificate"].ToString()));
            StreamReader reader = new StreamReader(stream);
            String content = reader.ReadToEnd();
            content = content.Replace("-----BEGIN CERTIFICATE-----", "");
            content = content.Replace("-----END CERTIFICATE-----", "");
            content = content.Replace("\r\n", "");
            return content;
        }

        public string Postauthxml_OnAUA(string authxml, string HttpWebRequesturl)
        {
            X509Certificate cert = X509Certificate.CreateFromCertFile(System.Web.HttpContext.Current.Server.MapPath(System.Configuration.ConfigurationManager.AppSettings["ClientCertificate"].ToString()));
            HttpWebRequesturl = getHttpWebRequesturl();
            string Urlencoded = HttpUtility.UrlEncode(HttpWebRequesturl);
            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create(Urlencoded);
            req.Method = "POST";
            req.ProtocolVersion = HttpVersion.Version11;
            req.ContentType = "application/xml";
            req.ClientCertificates.Add(cert);
            //   d1 = DateTime.Now;
            
            System.Net.ServicePointManager.CertificatePolicy =
                           new TrustAllCertificatePolicy();
            string content = authxml;

            req.ContentLength = content.Length;
            Stream wri = req.GetRequestStream();
            byte[] array = Encoding.UTF8.GetBytes(content);
            wri.Write(array, 0, array.Length);
            wri.Flush();
            wri.Close();
            HttpWebResponse HttpWResp = (HttpWebResponse)req.GetResponse();
            int resCode = Convert.ToInt32(HttpWResp.StatusCode);
            StreamReader reader = new StreamReader(HttpWResp.GetResponseStream(), System.Text.Encoding.UTF8);
            string resultData = reader.ReadToEnd();
            // d2 = DateTime.Now;
            string decodedresult = resultData;

            return decodedresult;

        }

        public class TrustAllCertificatePolicy : System.Net.ICertificatePolicy
        {
            public TrustAllCertificatePolicy()
            { }
            public bool CheckValidationResult(ServicePoint sp,
               System.Security.Cryptography.X509Certificates.
                X509Certificate cert, WebRequest req, int problem)
            {

                return true;
            }
        }
        public string ParseRespXML(string ResponseXML)
        {

            string ResRet = "";
            string Response = "";
            string Err = "";
            string output = "";

            XmlDocument Doc = new XmlDocument();
            Doc.LoadXml(ResponseXML);

            XmlElement root = Doc.DocumentElement;
            XmlNode ret_Y = root.SelectSingleNode("@ret");
            if (ret_Y == null)
            {
                ResRet = "Some Major Problem Occured";
            }
            else
            {

                if (String.Compare(ret_Y.Value.ToString(), "y", StringComparison.OrdinalIgnoreCase) == 0)
                {
                    ResRet = "Your Authentication is Successful ";
                    Response = ret_Y.Value.ToString();
                    Err = "";
                    output = Response;
                 //   DisplayKYCData(ResponseXML);
                }
                else if (String.Compare(ret_Y.Value.ToString(), "n", StringComparison.OrdinalIgnoreCase) == 0)
                {
                    Response = ret_Y.Value.ToString();

                    XmlNode ret_err = root.SelectSingleNode("@err");

                    Err = ret_err.Value.ToString();
                    ResRet = "Your Authentication Failed and the Error Code is:- " + Convert.ToString(ret_err.Value);
                    output = GetAuthErrorDescription(Err);
                }
                else
                {
                    ResRet = "Some Major Problem Occured";

                }
            }

            return output;
        }

        
        public string GetAuthErrorDescription(string err)
        {
            switch (err)
            {
                case "100":
                    return "100 - Pi (basic) attributes of demographic data did not match.";
                case "200":
                    return "200 - Pa (address) attributes of demographic data did not match";
                case "300":
                    return "300 - Biometric data did not match";
                case "310":
                    return "310 - Duplicate fingers used";
                case "311":
                    return "311 - Duplicate Irises used.";
                case "312":
                    return "312 - FMR and FIR cannot be used in same transaction";
                case "313":
                    return "313 - Single FIR record contains more than one finger";
                case "314":
                    return "314 - Number of FMR/FIR should not exceed 10";
                case "315":
                    return "315 - Number of IIR should not exceed 2";
                case "400":
                    return "400 - Invalid OTP value";
                case "401":
                    return "401 - Invalid TKN value";
                case "500":
                    return "500 - Invalid encryption of Skey";
                case "501":
                    return "501 - Invalid certificate identifier in ci attribute of Skey";
                case "502":
                    return "502 - Invalid encryption of Pid";
                case "503":
                    return "503 - Invalid encryption of Hmac";
                case "504":
                    return "504 - Session key re-initiation required due texpiry or key out of sync";
                case "505":
                    return "505 - Synchronized Key usage not allowed for the AUA";
                case "510":
                    return "510 - Invalid Auth XML format";
                case "511":
                    return "511 - Invalid PID XML format";
                case "520":
                    return "520 - Invalid device";
                case "521":
                    return "521 - Invalid FDC code under Meta tag";
                case "522":
                    return "522 - Invalid IDC code under Meta tag";
                case "530":
                    return "530 - Invalid authenticator code";
                case "540":
                    return "540 - Invalid Auth XML version";
                case "541":
                    return "541 - Invalid PID XML version";
                case "542":
                    return "542 - AUA not authorized for ASA. This error will be returned if AUA and ASA dnot have linking in the portal";
                case "543":
                    return "543 - Sub-AUA not associated with AUA. This error will be returned if Sub-AUA specified in sa attribute is not added as Sub-AUA in portal";
                case "550":
                    return "550 - Invalid Uses element attributes";
                case "551":
                    return "551 - Invalid tid value for registered device";
                case "552":
                    return "552 - Invalid registered device key, please reset";
                case "553":
                    return "553 - Invalid registered device HOTP, please reset";
                case "554":
                    return "554 - Invalid registered device encryption";
                case "555":
                    return "555 - Mandatory reset required for registered device";
                case "561":
                    return "561 - Request expired (Pid->ts value is older than N hours where N is a configured threshold in authentication server)";
                case "562":
                    return "562 - Timestamp value is future time (value specified Pid->ts is ahead of authentication server time beyond acceptable threshold)";
                case "563":
                    return "563 - Duplicate request (this error occurs when exactly same authentication request was re-sent by AUA)";
                case "564":
                    return "564 - HMAC Validation failed";
                case "565":
                    return "565 - AUA license has expired";
                case "566":
                    return "566 - Invalid non-decryptable license key";
                case "567":
                    return "567 - Invalid input (this error occurs when some unsupported characters were found in Indian language values, lname or lav)";
                case "568":
                    return "568 - Unsupported Language";
                case "569":
                    return "569 - Digital signature verification failed (means that authentication request XML was modified after it was signed)";
                case "570":
                    return "570 - Invalid key infin digital signature (this means that certificate used for signing the authentication request is not valid – it is either expired, or does not belong tthe AUA or is not created by a well-known Certification Authority)";
                case "571":
                    return "571 - PIN Requires reset (this error will be returned if resident is using the default PIN which needs tbe reset before usage)";
                case "572":
                    return "572 - Invalid biometric position";
                case "573":
                    return "573 - Pi usage not allowed as per license";
                case "574":
                    return "574 - Pa usage not allowed as per license";
                case "575":
                    return "575 - Pfa usage not allowed as per license";
                case "576":
                    return "576 - FMR usage not allowed as per license";
                case "577":
                    return "577 - FIR usage not allowed as per license";
                case "578":
                    return "578 - IIR usage not allowed as per license";
                case "579":
                    return "579 - OTP usage not allowed as per license";
                case "580":
                    return "580 - PIN usage not allowed as per license";
                case "581":
                    return "581 - Fuzzy matching usage not allowed as per license";
                case "582":
                    return "582 - Local language usage not allowed as per license";
                case "584":
                    return "584 - Invalid pincode in LOV attribute under Meta tag";
                case "585":
                    return "585 - Invalid geo-code in LOV attribute under Meta tag";
                case "710":
                    return "710 - Missing Pi data as specified in Uses";
                case "720":
                    return "720 - Missing Pa data as specified in Uses";
                case "721":
                    return "721 - Missing Pfa data as specified in Uses";
                case "730":
                    return "730 - Missing PIN data as specified in Uses";
                case "740":
                    return "740 - Missing OTP data as specified in Uses";
                case "800":
                    return "800 - Invalid biometric data";
                case "810":
                    return "810 - Missing biometric data as specified in Uses";
                case "811":
                    return "811 - Missing biometric data in CIDR for the given Aadhaar number";
                case "812":
                    return "812 - Resident has not done Best Finger Detection. Application should initiate BFD application thelp resident identify their best fingers. See Aadhaar Best Finger Detection API specification.";
                case "820":
                    return "820 - Missing or empty value for bt attribute in Uses element";
                case "821":
                    return "821 - Invalid value in the bt attribute of Uses element";
                case "901":
                    return "901 - Nauthentication data found in the request (this corresponds ta scenariwherein none of the auth data – Demo, Pv, or Bios – is present)";
                case "902":
                    return "902 - Invalid dob value in the Pi element (this corresponds ta scenarios wherein dob attribute is not of the format YYYY or YYYY-MM-DD, or the age of resident is not in valid range)";
                case "910":
                    return "910 - Invalid mv value in the Pi element";
                case "911":
                    return "911 - Invalid mv value in the Pfa element";
                case "912":
                    return "912 - Invalid ms value";
                case "913":
                    return "913 - Both Pa and Pfa are present in the authentication request (Pa and Pfa are mutually exclusive)";
                case "930 t939":
                    return "930 t939 - Technical error that are internal tauthentication server";
                case "940":
                    return "940 - Unauthorized ASA channel";
                case "941":
                    return "941 - Unspecified ASA channel";
                case "980":
                    return "980 - Unsupported option";
                case "997":
                    return "997 - Invalid Aadhaar status (Aadhaar is not in authenticatable status)";
                case "998":
                    return "998 - Invalid Aadhaar Number";
                case "999":

                    return "999 - Unknown error";
                default:
                    return "Some Problem Occured";
            }
        }
    }

}