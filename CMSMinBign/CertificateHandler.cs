using System;
using System.Security.Cryptography.X509Certificates;

namespace CMSMinBign
{
    internal class CertificateHandler : IDisposable
    {
        private X509Store store { get; set; }

        public CertificateHandler()
        {
            store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
        }

        public X509Certificate2Collection getCertList()
        {
            X509Certificate2Collection certificates = store.Certificates;
            store.Close();
            return certificates;
        }

        public X509Certificate2 getCertByName(string name)
        {
            try
            {
                X509Certificate2Enumerator enumerator = getCertList().GetEnumerator();
                while (enumerator.MoveNext())
                {
                    X509Certificate2 current = enumerator.Current;
                    if (current.GetNameInfo(X509NameType.SimpleName, forIssuer: false) == name)
                    {
                        return current;
                    }
                }
            }
            catch (Exception)
            {
            }
            return null;
        }

        public void Dispose()
        {
            store.Close();
            Dispose();
        }
    }
}
