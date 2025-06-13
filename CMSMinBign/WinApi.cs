using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CMSMinBign
{
    public class WinApi
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CRYPT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszContainerName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszProvName;

            public uint dwProvType;

            public uint dwFlags;

            public uint cProvParam;

            public IntPtr rgProvParam;

            public uint dwKeySpec;
        }

        [DllImport("crypt32.dll")]
        public static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);

        public CRYPT_KEY_PROV_INFO GetCertificateContextProperty(X509Certificate2 certificate)
        {
            IntPtr handle = certificate.Handle;
            uint pcbData = 0u;
            if (CertGetCertificateContextProperty(handle, 2u, IntPtr.Zero, ref pcbData))
            {
                IntPtr intPtr = Marshal.AllocHGlobal((int)pcbData);
                try
                {
                    if (CertGetCertificateContextProperty(handle, 2u, intPtr, ref pcbData))
                    {
                        return (CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(intPtr, typeof(CRYPT_KEY_PROV_INFO));
                    }
                    throw new Exception("Failed to fetch the Certificate Context Property, possibly due to the certificate being modified during the call.  Please try again!");
                }
                finally
                {
                    Marshal.FreeHGlobal(intPtr);
                }
            }
            throw new Exception("Failed to fetch the Certificate Context Property");
        }
    }
}
