using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using System.Globalization;

namespace CMSMinBign
{
    internal class App
    {
        private static CertificateHandler handler;

        public static List<ShortCertificate> getCerts()
        {
            List<ShortCertificate> availableCerts = new List<ShortCertificate>();
            try
            {
                X509Certificate2Collection certList = new CertificateHandler().getCertList();
                for (int i = 0; i < certList.Count; i++)
                {
                    for (int j = 0; j < certList[i].Extensions.Count; j++)
                    {
                        if (!(certList[i].NotAfter < DateTime.Now) && certList[i].Extensions[j].Oid.Value == "1.2.112.1.2.1.1.1.1.2")
                        {
                            Certificate certificate = ConvertCert(certList[i]);
                            ShortCertificate info = new ShortCertificate();
                            info.Index = i;
                            info.Name = certList[i].GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                            info.Owner = certificate.subject.surname + " " + certificate.subject.name;
                            info.Serial = certificate.serial;
                            info.Unp = certificate.subject.unp;


                            availableCerts.Add(info);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return availableCerts;
        }

        private static Certificate ConvertCert(X509Certificate2 tempCert)
        {
            //IL_00a1: Unknown result type (might be due to invalid IL or missing references)
            Certificate certificate = new Certificate();
            certificate.subject = new Subject();
            for (int i = 0; i < tempCert.Extensions.Count; i++)
            {
                string value = tempCert.Extensions[i].Oid.Value;
                if (!(value == "1.2.112.1.2.1.1.1.1.2"))
                {
                    if (value == "1.2.112.1.2.1.1.5.1")
                    {
                        certificate.subject.position = parseStringBMP(tempCert.Extensions[i].RawData);
                    }
                }
                else
                {
                    certificate.subject.unp = parseStringBMP(tempCert.Extensions[i].RawData);
                }
            }
            Asn1Object obj = ((Asn1Encodable)new X509CertificateParser().ReadCertificate(tempCert.RawData).SubjectDN).ToAsn1Object();
            foreach (Asn1Encodable item in (Asn1Sequence)((obj is DerSequence) ? obj : null))
            {
                DerSet val = (DerSet)(object)((item is DerSet) ? item : null);
                if (val == null)
                {
                    continue;
                }
                Asn1Encodable obj2 = ((Asn1Set)val)[0];
                DerSequence val2 = (DerSequence)(object)((obj2 is DerSequence) ? obj2 : null);
                foreach (Asn1Encodable item2 in (Asn1Sequence)val2)
                {
                    DerObjectIdentifier val3 = (DerObjectIdentifier)(object)((item2 is DerObjectIdentifier) ? item2 : null);
                    if (val3 != null)
                    {
                        string text = ((object)((Asn1Sequence)val2)[1]).ToString();
                        switch (val3.Id)
                        {
                            case "2.5.4.3":
                                certificate.subject.company = text;
                                break;
                            case "2.5.4.10":
                                certificate.subject.organization = text;
                                break;
                            case "2.5.4.6":
                                certificate.subject.country = text;
                                break;
                            case "2.5.4.7":
                                certificate.subject.locality = text;
                                break;
                            case "2.5.4.9":
                                certificate.subject.street = text;
                                break;
                            case "2.5.4.4":
                                certificate.subject.surname = text;
                                break;
                            case "2.5.4.41":
                                certificate.subject.name = text;
                                break;
                        }
                    }
                }
            }
            certificate.serial = tempCert.SerialNumber;
            certificate.effectiveDate = tempCert.NotBefore.ToString("dd.MM.yyyy H:mm:ss", CultureInfo.InvariantCulture);
            certificate.expirationDate = tempCert.NotAfter.ToString("dd.MM.yyyy H:mm:ss", CultureInfo.InvariantCulture);
            return certificate;
        }

        private static string parseStringBMP(byte[] arr)
        {
            string text = "";
            int num = arr.Length - arr[1];
            if (arr.Length > 127)
            {
                num = arr.Length - arr[2];
            }
            int num2 = num;
            while (num2 < arr.Length)
            {
                int num3 = arr[num2++];
                int num4 = arr[num2++];
                text += (char)((num3 << 8) | num4);
            }
            return text;
        }

        public static byte[] Sign(int index, byte[] fileForSign, string pin)
        {
            Cryption cryption = new Cryption(getCert(index));
            return cryption.SignByCertificate(fileForSign, cryption.MyCertificate(), pin);
        }

        public static X509Certificate2 getCert(int index)
        {
            handler = new CertificateHandler();
            return handler.getCertList()[index];
        }
    }
}
