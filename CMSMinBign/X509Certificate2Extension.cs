using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CMSMinBign
{
    internal static class X509Certificate2Extension
    {
        internal static class SafeNativeMethods
        {
            internal enum CryptContextFlags
            {
                None = 0,
                Silent = 0x40
            }

            internal enum CertificateProperty
            {
                None,
                CryptoProviderHandle
            }

            public const int AT_SIGNATURE = 2;

            public const int STB_P_34_101_31 = 32819;

            internal const int PP_SIGNATURE_PIN = 33;

            internal const int PP_KEYEXCHANGE_PIN = 32;

            internal const uint CRYPT_ACQUIRE_SILENT_FLAG = 64u;

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptAcquireContext(ref IntPtr hProv, string containerName, string providerName, int providerType, CryptContextFlags flags);

            [DllImport("Crypt32.dll", SetLastError = true)]
            public static extern bool CertFreeCertificateContext(IntPtr pCertContext);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptSetProvParam(IntPtr hProv, int dwParam, byte[] pbData, int dwFlags);

            [DllImport("CRYPT32.DLL", SetLastError = true)]
            internal static extern bool CertSetCertificateContextProperty(IntPtr pCertContext, CertificateProperty propertyId, uint dwFlags, IntPtr pvData);

            public static void Execute(Func<bool> action)
            {
                if (!action())
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
        }

        public static IntPtr SetPinForPrivateKey(this X509Certificate2 certificate, string pin)
        {
            WinApi winApi = new WinApi();
            WinApi.CRYPT_KEY_PROV_INFO _ctx = winApi.GetCertificateContextProperty(certificate);
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            IntPtr providerHandle = IntPtr.Zero;
            byte[] pinBuffer = Encoding.Default.GetBytes(pin);
            try
            {
                SafeNativeMethods.Execute(() => SafeNativeMethods.CryptAcquireContext(ref providerHandle, _ctx.pwszContainerName, _ctx.pwszProvName, (int)_ctx.dwProvType, SafeNativeMethods.CryptContextFlags.Silent));
                SafeNativeMethods.Execute(() => SafeNativeMethods.CryptSetProvParam(providerHandle, 32, pinBuffer, 0));
                SafeNativeMethods.Execute(() => SafeNativeMethods.CertSetCertificateContextProperty(certificate.Handle, SafeNativeMethods.CertificateProperty.CryptoProviderHandle, 0u, providerHandle));
            }
            catch (Exception)
            {
                throw new Exception("Неверный пароль");
            }
            return providerHandle;
        }

        public static void freeContext(this X509Certificate2 certificate, IntPtr phProv)
        {
            if (phProv != IntPtr.Zero)
            {
                SafeNativeMethods.CryptReleaseContext(phProv, 0);
            }
        }
    }
}
