using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

public static class Crypt
{
    [DllImport("Crypt32.dll", SetLastError = true)]
    public static extern bool CryptRetrieveTimeStamp(
        string pszTsaUrl,
        uint dwFlags,
        uint dwTimeout,
        string pszDigestAlgorithm,
        IntPtr pTimestampPara,
        IntPtr pbData,
        uint cbData,
        out IntPtr ppTsContext,
        uint dwReserved1,
        uint dwReserved2);

    [DllImport("Crypt32.dll", SetLastError = true)]
    public static extern void CryptMemFree(IntPtr pv);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void LocalFree(IntPtr hMem);
}

public static class WinApiExtensions
{
    public static void VerifyWinapiTrue(this bool result)
    {
        if (!result)
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new System.ComponentModel.Win32Exception(errorCode);
        }
    }
}

class Program
{
    public const uint TIMESTAMP_VERIFY_CONTEXT_SIGNATURE = 0x00000020;

    static void Main(string[] args)
    {
        var ecpFilePath = "data.bin.sig";
        byte[] ecp = File.ReadAllBytes(ecpFilePath);
        var ecpBase64 = Convert.ToBase64String(ecp, Base64FormattingOptions.InsertLineBreaks);
        Span<byte> nonce = stackalloc byte[16];
        RandomNumberGenerator.Create().GetBytes(nonce);
        var tbh = Encoding.Unicode.GetBytes(ecpBase64);
        Oid digestOid = new Oid("1.3.14.3.2.26"); // OID для SHA-1

        var tst = RetriveTimestamp(tbh.AsSpan(), digestOid, nonce, "http://tsp.pkitrans.ru/tspca1_niias/tsp.srf", TimeSpan.FromSeconds(15));
        Console.WriteLine(tst);

        Console.WriteLine("Обработка завершена!");
    }

    public static unsafe byte[] RetriveTimestamp(ReadOnlySpan<byte> data, Oid tspDigestOid, ReadOnlySpan<byte> nonce, string tsaUri, TimeSpan timeout) {
        var tspReq = new CRYPT_TIMESTAMP_PARA();
        tspReq.fRequestCerts = true;
        fixed (byte* pData = data, pNonce = nonce) {
            if (nonce.Length > 0)
            {
                tspReq.Nonce.cbData = (uint)nonce.Length;
                tspReq.Nonce.pbData = (nint)pNonce;
            }

            nint pTsContext;
            // CryptRetrieveTimeStamp(tsaUri, TIMESTAMP_NO_AUTH_RETRIEVAL | TIMESTAMP_VERIFY_CONTEXT_SIGNATURE, 
            //     timeout.Milliseconds, tspDigestOid.Value, (nint)(&tspReq), (nint)pData, (uint)data.Length,
            //     (nint)(&pTsContext), 0, 0).VerifyWinapiTrue();

            Crypt.CryptRetrieveTimeStamp(tsaUri, TIMESTAMP_VERIFY_CONTEXT_SIGNATURE, 
            (uint)timeout.TotalMilliseconds, tspDigestOid.Value, (nint)(&tspReq), (nint)pData, (uint)data.Length,
            out pTsContext, 0, 0).VerifyWinapiTrue();

            try
            {
                var tsContext = new ReadOnlySpan<CRYPT_TIMESTAMP_CONTEXT>(pTsContext.ToPointer(), 1);
                var tst = new ReadOnlySpan<byte>(tsContext[0].pbEncoded.ToPointer(), (int)tsContext[0].cbEncoded);
                return tst.ToArray();
            }
            finally
            {
                if (pTsContext != 0)
                    Crypt.CryptMemFree(pTsContext);
            }
        }
    }

    internal struct CRYPT_TIMESTAMP_PARA
    {
        // internal IntPtr pszTSAPolicyId;
        internal bool fRequestCerts;
        internal CRYPTOAPI_BLOB Nonce;
        // internal int cExtension;
        // internal IntPtr rgExtension;
    }

    internal struct CRYPTOAPI_BLOB
    {
        internal uint cbData;
        internal IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_TIMESTAMP_CONTEXT
    {
        public uint cbEncoded; // Размер закодированных данных
        public IntPtr pbEncoded; // Указатель на закодированные данные
        public IntPtr pSigner; // Указатель на информацию о подписчике (если необходимо)
        // Добавьте другие поля, если они вам нужны
    }
}
