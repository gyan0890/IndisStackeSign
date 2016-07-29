using ClassLibrary1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace AllAuthClass
{
    public class AuthKYC_OTP
    {
        private void SetAttribute(XmlDocument XD, XmlNode XN, string AttName, string AttValue)
        {
            XmlAttribute Att = XN.Attributes.Append(XD.CreateAttribute(AttName));
            Att.InnerText = AttValue;
        }
        public string GenPIDXML_KYC_OTP(string OTP = "", string ts = "")
        {
            XmlDocument XDPid = new XmlDocument();
            XmlNode docNode = XDPid.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            XDPid.AppendChild(docNode);
            XmlNode Root = XDPid.AppendChild(XDPid.CreateElement("Pid"));
            SetAttribute(XDPid, Root, "ts", ts);
            XmlNode Pv = Root.AppendChild(XDPid.CreateElement("Pv"));
            SetAttribute(XDPid, Pv, "otp", OTP);
            return XDPid.InnerXml;
        }

        public string GenAuthXML_KYC_OTP(string aadharNo = "", string publicKey = "", string pid = "", string txn = "")
        {

           
            if (!string.IsNullOrEmpty(aadharNo))
            {
                txn = aadharNo + System.DateTime.Now.ToString("yyyyMMddHHmmss:fff");
                txn = "UKC:" + txn;
            }
            else
            {
                txn = "UKC:" + txn;
            }
            
           
        
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
            SetAttribute(XDAuth, Root, "ac", "STGNIC0011");
            SetAttribute(XDAuth, Root, "sa", "AIMS");
            SetAttribute(XDAuth, Root, "ver", "1.6");
            SetAttribute(XDAuth, Root, "txn", txn);
            SetAttribute(XDAuth, Root, "lk", "AIMS");
            SetAttribute(XDAuth, Root, "xmlns", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0");


            XmlNode Meta = Root.AppendChild(XDAuth.CreateElement("Meta", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            SetAttribute(XDAuth, Meta, "udc", "NICTEST");
            SetAttribute(XDAuth, Meta, "fdc", "NC");
            SetAttribute(XDAuth, Meta, "idc", "NA");
            SetAttribute(XDAuth, Meta, "pip", "127.0.0.1");
            SetAttribute(XDAuth, Meta, "lot", "P");
            SetAttribute(XDAuth, Meta, "lov", "110092");

            XmlNode Skey = Root.AppendChild(XDAuth.CreateElement("Skey", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            SetAttribute(XDAuth, Skey, "ci", certificateIdentifier);
            Skey.InnerXml = Convert.ToBase64String(encryptedSessionKey);

            XmlNode Uses = Root.AppendChild(XDAuth.CreateElement("Uses", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            XDAuth.DocumentElement.AppendChild(Uses);
            SetAttribute(XDAuth, Uses, "otp", "y");
            SetAttribute(XDAuth, Uses, "pin", "n");
            SetAttribute(XDAuth, Uses, "pfa", "n");
            SetAttribute(XDAuth, Uses, "pa", "n");
            SetAttribute(XDAuth, Uses, "pi", "n");
            SetAttribute(XDAuth, Uses, "bio", "n");


            XmlNode Data = Root.AppendChild(XDAuth.CreateElement("Data", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            SetAttribute(XDAuth, Data, "type", "X");
            Data.InnerXml = Convert.ToBase64String(encXMLPIDData);

            XmlNode Hmac2 = Root.AppendChild(XDAuth.CreateElement("Hmac", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0"));
            Hmac2.InnerXml = Convert.ToBase64String(encryptedHmacBytes);

            return XDAuth.OuterXml;
        }

        public string GenKycXML(string allRad = "", string ts = "")
        {

            XmlDocument XDKyc = new XmlDocument();
            XmlNode docNode = XDKyc.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            XDKyc.AppendChild(docNode);

            XmlNode Root = XDKyc.AppendChild(XDKyc.CreateElement("Kyc"));
            SetAttribute(XDKyc, Root, "xmlns", "http://www.uidai.gov.in/kyc/uid-kyc-request/1.0");
            SetAttribute(XDKyc, Root, "ver", "1.0");
            SetAttribute(XDKyc, Root, "ts", ts);
            SetAttribute(XDKyc, Root, "ra", "O");
            SetAttribute(XDKyc, Root, "rc", "Y");
            SetAttribute(XDKyc, Root, "mec", "Y");
            SetAttribute(XDKyc, Root, "lr", "Y");
            SetAttribute(XDKyc, Root, "de", "N");
            XmlNode Rad = Root.AppendChild(XDKyc.CreateElement("Rad"));
            byte[] allRadXmlBytes = Encoding.UTF8.GetBytes(allRad);
            Rad.InnerXml = Convert.ToBase64String(allRadXmlBytes);
            return XDKyc.OuterXml;


        }
        public string GeneSignXML(string alldata = "", string ts = "")
        {
            XmlDocument XDKyc = new XmlDocument();
            XmlNode docNode = XDKyc.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            XDKyc.AppendChild(docNode);
            XmlNode Root = XDKyc.AppendChild(XDKyc.CreateElement("Esign"));
            SetAttribute(XDKyc, Root, "ver", "1.0");
            SetAttribute(XDKyc, Root, "sc", "Y");
            SetAttribute(XDKyc, Root, "ts", ts);
            SetAttribute(XDKyc, Root, "txn", "1de27731-17a3-47b5-b451-b05f3c0cf0g5");
            SetAttribute(XDKyc, Root, "aspId", "ASPDIETY");
            SetAttribute(XDKyc, Root, "esignClass", "1");
            SetAttribute(XDKyc, Root, "preferredCa", "emudra");
            SetAttribute(XDKyc, Root, "gatewayPin", "");
            XmlNode Root1 = Root.AppendChild(XDKyc.CreateElement("Input"));
            Root1.InnerXml = "10c4b860e03ae471c5aba112ba7f5cd0dad896b5652eb1ba83dda7f309733c90";
            XmlNode Rad = Root.AppendChild(XDKyc.CreateElement("Aadhaar"));
            byte[] allRadXmlBytes = Encoding.UTF8.GetBytes(alldata);
            Rad.InnerXml = Convert.ToBase64String(allRadXmlBytes);
            XmlNode Rad1 = Root.AppendChild(XDKyc.CreateElement("Signature"));
            SetAttribute(XDKyc, Rad1, "xmlns", "http://www.w3.org/2000/09/xmldsig#");
            XmlNode Rad2 = Rad1.AppendChild(XDKyc.CreateElement("SignedInfo"));
            XmlNode Rad3 = Rad2.AppendChild(XDKyc.CreateElement("CanonicalizationMethod"));
            SetAttribute(XDKyc, Rad3, "Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            XmlNode Rad4 = Rad2.AppendChild(XDKyc.CreateElement("SignatureMethod"));
            SetAttribute(XDKyc,Rad4,"Algorithm","http://www.w3.org/2000/09/xmldsig#rsa-sha1");
            XmlNode Rad5 = Rad2.AppendChild(XDKyc.CreateElement("Reference"));
            SetAttribute(XDKyc, Rad5, "URI", "");
            XmlNode Rad6 = Rad5.AppendChild(XDKyc.CreateElement("Transforms"));
            XmlNode Rad7 = Rad6.AppendChild(XDKyc.CreateElement("Transform"));
            SetAttribute(XDKyc, Rad7, "Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
            XmlNode Rad8 = Rad6.AppendChild(XDKyc.CreateElement("Transform"));
            SetAttribute(XDKyc, Rad8, "Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
            XmlNode Rad9 = Rad5.AppendChild(XDKyc.CreateElement("DigestMethod"));
            SetAttribute(XDKyc, Rad9, "Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
            XmlNode Rad10 = Rad5.AppendChild(XDKyc.CreateElement("DigestValue"));
            Rad10.InnerXml = "0fircy1Ie03VMnoWj5PmH2p6zpM=";
            XmlNode Rad11 = Rad1.AppendChild(XDKyc.CreateElement("SignatureValue"));
            Rad11.InnerXml = "k0WldtTOzWnEftGSZ9c1pDLe1ojHGZ+E4CuJYWofV5pw9OqzvZNAwr3yJiIokcYDlam28b2vwUHMUs1jlPIuru0nEzYsTn2D8UHzmzKgrIi4NrKdFxiRlpzQhIaRXSybhOrRNIZFU7MhfQjqdpwNJcPw5F1de772C2Ubqptu1sg6sFxN8yWYUMZPd3qRn/9ZDY81U3vLRa461yZMEUgCwfflNYnjQSY2lm/YbcoyyoeLObgmWYmSX1MqiCYPl3N27BIic4s/7ZaKzmbfu0ckUT9NlMVbscwAY50U2Zup77sJUiPVCUbs6zTB6x5f71OF4NEhL1E3qRdzrSub4tspoA==";
            XmlNode Rad12 = Rad1.AppendChild(XDKyc.CreateElement("KeyInfo"));
            XmlNode Rad13 = Rad12.AppendChild(XDKyc.CreateElement("X509Data"));
            XmlNode Rad14 = Rad13.AppendChild(XDKyc.CreateElement("X509SubjectName"));
            Rad14.InnerXml = "CN=DS DEPARTMENT OF ELECTRONICS AND INFORMATION TECHNOLOGY 01, OID.2.5.4.51=ELECTRONICS NIKETAN 6 CGO COMPLEX, STREET=LODHI ROAD, S=Delhi, PostalCode=110003, OU=CID - 940960, O=DEPARTMENT OF ELECTRONICS AND INFORMATION TECHNOLOGY, C=IN";
            XmlNode Rad15 = Rad13.AppendChild(XDKyc.CreateElement("X509Certificate"));
            Rad15.InnerXml = "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";
            return XDKyc.OuterXml;
        }
    }
}
