using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Formats.Asn1;
using Org.BouncyCastle.Cms;

namespace CMSMinBign
{
    internal class Cryption
    {
        private X509Certificate2 cert;

        public Cryption(string Name)
        {
            try
            {
                cert = LoadCertificate(StoreLocation.CurrentUser, Name);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public Cryption()
        {
        }

        public Cryption(X509Certificate2 cert)
        {
            this.cert = cert;
        }

        public X509Certificate2 MyCertificate()
        {
            return cert;
        }

        private X509Certificate2 LoadCertificate(StoreLocation storeLocation, string certificateName)
        {
            X509Store x509Store = new X509Store(storeLocation);
            x509Store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = x509Store.Certificates;
            X509Certificate2 x509Certificate = null;
            foreach (X509Certificate2 item in (X509CertificateCollection)certificates)
            {
                if (item.Subject.Contains(certificateName))
                {
                    x509Certificate = item;
                    break;
                }
            }
            if (x509Certificate == null)
            {
                x509Store.Close();
            }
            return x509Certificate;
        }

        public bool ValidateCertificate(X509Certificate2 x509)
        {
            DateTime value = DateTime.Parse(x509.GetExpirationDateString());
            return DateTime.Now.CompareTo(value) < 0;
        }

        public byte[] SignByCertificate(byte[] fileForSign, X509Certificate2 certificate, string containerPassw)
        {
            if (containerPassw != string.Empty)
            {
                certificate.SetPinForPrivateKey(containerPassw);
            }
            ContentInfo val = new ContentInfo(fileForSign);
            SignedCms val2 = new SignedCms(SubjectIdentifierType.SubjectKeyIdentifier, val, true);
            CmsSigner val3 = new CmsSigner(SubjectIdentifierType.SubjectKeyIdentifier, certificate);           
            

            if (containerPassw != string.Empty)
            {
                val2.ComputeSignature(val3, true);
            }
            else
            {
                val2.ComputeSignature(val3, false);
            }
            byte[] array = val2.Encode();
            return CreateSequenceOfTypeEncapContentInfo(array);
        }


        public byte[] CreateSequenceOfTypeEncapContentInfo(byte[] bytes)
        {
            var data = new CmsSignedData(bytes);
            var signer = data.GetSignerInfos().GetSigners()[0];
          
            var writer = new AsnWriter(AsnEncodingRules.DER);
       
            using (writer.PushSequence())
            {
                writer.WriteInteger(3);
                writer.WriteEncodedValue(signer.SignerInfo.SignerID.GetEncoded());
                
                var second = new AsnWriter(AsnEncodingRules.DER);

                using (second.PushSequence())
                {
                    second.WriteObjectIdentifier(signer.DigestAlgOid);
                    second.WriteNull();
                }

                var third = new AsnWriter(AsnEncodingRules.DER);

                using (third.PushSequence())
                {
                    third.WriteObjectIdentifier(signer.SignatureAlgorithm.Algorithm.ToString());
                    third.WriteNull();
                }

                writer.WriteEncodedValue(second.Encode());
                writer.WriteEncodedValue(third.Encode());
                writer.WriteOctetString(signer.GetSignature());
            }

            return writer.Encode();
        }

        public void checkPassword(X509Certificate2 certificate, string containerPassw)
        {
            certificate.SetPinForPrivateKey(containerPassw);
        }
    }

}
