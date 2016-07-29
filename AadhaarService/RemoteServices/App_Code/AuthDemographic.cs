using ClassLibrary1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace AllAuthClass
{
    public class AuthDemographic
    {
        private void SetAttribute(XmlDocument XD, XmlNode XN, string AttName, string AttValue)
        {
            XmlAttribute Att = XN.Attributes.Append(XD.CreateAttribute(AttName));
            Att.InnerText = AttValue;
        }

        public string GenPIDXML_Demographic(string PersonName = "", string PersonGender = "", string PersonDOB = "", string PersonPhone = "", string MatchScheme = "E", string MatchValue = "100", string PersonPincode = "")
        {

            string ts = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");
            XmlDocument XDPid = new XmlDocument();
            XmlNode docNode = XDPid.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            XDPid.AppendChild(docNode);
            XmlNode Root = XDPid.AppendChild(XDPid.CreateElement("Pid"));
            SetAttribute(XDPid, Root, "ts", ts);

            XmlNode Demo = Root.AppendChild(XDPid.CreateElement("Demo"));
            //if (!string.IsNullOrEmpty(PersonName))
            //{
                XmlNode Pi = Demo.AppendChild(XDPid.CreateElement("Pi"));
                SetAttribute(XDPid, Pi, "ms", MatchScheme);
                SetAttribute(XDPid, Pi, "mv", MatchValue);

                if (!string.IsNullOrEmpty(PersonName))
                    SetAttribute(XDPid, Pi, "name", PersonName.Trim());
                if (!string.IsNullOrEmpty(PersonGender))
                    SetAttribute(XDPid, Pi, "gender", PersonGender);
                if (!string.IsNullOrEmpty(PersonDOB))
                    SetAttribute(XDPid, Pi, "dob", PersonDOB);
                if (!string.IsNullOrEmpty(PersonPhone))
                    SetAttribute(XDPid, Pi, "phone", PersonPhone);

                if (!string.IsNullOrEmpty(PersonPincode))
                {
                    XmlNode Pa = Demo.AppendChild(XDPid.CreateElement("Pa"));
                    MatchScheme = "E";//Default Value
                    SetAttribute(XDPid, Pa, "ms", MatchScheme);
                    if (!string.IsNullOrEmpty(PersonPincode))
                        SetAttribute(XDPid, Pa, "pc", PersonPincode);
                //}

            }
            return XDPid.InnerXml;
        }


        private static string GetSHA1HashData(string text)
        {
            Encoding enc = Encoding.Default;
            byte[] buffer = enc.GetBytes(text);
            SHA1CryptoServiceProvider cryptoTransformSha1 = new SHA1CryptoServiceProvider();
            string hash = BitConverter.ToString(cryptoTransformSha1.ComputeHash(buffer)).Replace("-", "");
            return hash;
        }


        public string GenAuthXML_Demographic(string aadharNo="", string PersonName="", string PersonPincode="", string publicKey="", string AllDetailsEntered="", string pid="")
        {
            //Generate Own Transaction ID for Identification of rach transaction
            string TxnHashVal = GetSHA1HashData(AllDetailsEntered);

            Enc xx = new Enc(Convert.FromBase64String(publicKey));
            //Generate Session Key
            byte[] sessionKey = xx.generateSessionKey();
            //Now Encrypt Session Key using Public Certificate of UIDAI
            byte[] encryptedSessionKey = xx.encryptUsingPublicKey(sessionKey);

            byte[] pidXmlBytes = Encoding.UTF8.GetBytes(pid);
            //Encrypt PID block using Session Key
            byte[] encXMLPIDData = xx.encryptUsingSessionKey(sessionKey, pidXmlBytes);
            //Calculate HMAC of PID Block
            byte[] hmac = xx.generateSha256Hash(pidXmlBytes);
            //Encrypt HMAC using Session Key
            byte[] encryptedHmacBytes = xx.encryptUsingSessionKey(sessionKey, hmac);
            //Get Certificate Identifier from Public Key
            string certificateIdentifier = xx.getCertificateIdentifier();
            XmlDocument XDAuth = new XmlDocument();
            XmlNode docNode = XDAuth.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            XDAuth.AppendChild(docNode);
            XmlNode Root = XDAuth.AppendChild(XDAuth.CreateElement("Auth", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            SetAttribute(XDAuth, Root, "uid", aadharNo.Trim());
            SetAttribute(XDAuth, Root, "tid", "public");
            SetAttribute(XDAuth, Root, "sa", "NICDEM");
            SetAttribute(XDAuth, Root, "txn", TxnHashVal);
            SetAttribute(XDAuth, Root, "xmlns", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0");
            XmlNode Uses = Root.AppendChild(XDAuth.CreateElement("Uses", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            XDAuth.DocumentElement.AppendChild(Uses);


            if (!string.IsNullOrEmpty(PersonPincode) && !string.IsNullOrEmpty(PersonName))
            {
                SetAttribute(XDAuth, Uses, "pi", "y");
                SetAttribute(XDAuth, Uses, "pa", "y");
            }
            else
            {
                if (!string.IsNullOrEmpty(PersonPincode))
                {
                    SetAttribute(XDAuth, Uses, "pi", "n");
                    SetAttribute(XDAuth, Uses, "pa", "y");

                }
                else
                {
                    SetAttribute(XDAuth, Uses, "pi", "y");
                    SetAttribute(XDAuth, Uses, "pa", "n");
                }
            }
            SetAttribute(XDAuth, Uses, "pfa", "n");
            SetAttribute(XDAuth, Uses, "bio", "n");
            SetAttribute(XDAuth, Uses, "bt", "");
            SetAttribute(XDAuth, Uses, "pin", "n");
            SetAttribute(XDAuth, Uses, "otp", "n");
            XmlNode Meta = Root.AppendChild(XDAuth.CreateElement("Meta", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            SetAttribute(XDAuth, Meta, "udc", "NICTEST");
            SetAttribute(XDAuth, Meta, "pip", "127.0.0.1");
            SetAttribute(XDAuth, Meta, "fdc", "NC");
            SetAttribute(XDAuth, Meta, "idc", "NA");
            SetAttribute(XDAuth, Meta, "lot", "P");
            SetAttribute(XDAuth, Meta, "lov", "110092");
            XmlNode Skey = Root.AppendChild(XDAuth.CreateElement("Skey", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            SetAttribute(XDAuth, Skey, "ci", certificateIdentifier);
            Skey.InnerXml = Convert.ToBase64String(encryptedSessionKey);
            XmlNode Data = Root.AppendChild(XDAuth.CreateElement("Data", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            SetAttribute(XDAuth, Data, "type", "X");
            Data.InnerXml = Convert.ToBase64String(encXMLPIDData);

            XmlNode Hmac2 = Root.AppendChild(XDAuth.CreateElement("Hmac", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            Hmac2.InnerXml = Convert.ToBase64String(encryptedHmacBytes);

            return XDAuth.OuterXml;
        }



    }
}
