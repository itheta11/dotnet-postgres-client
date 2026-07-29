using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using PgClient.Utilities;

namespace PgClient.Ssl;

/// Performs the pre-startup SSLRequest handshake and upgrades to an
/// <see cref="SslStream"/> when the server accepts TLS.
internal static class SslNegotiator
{
    private const int SslRequestCode = 80877103;

    /// Returns the stream to use for subsequent Postgres protocol traffic and
    /// whether TLS was actually negotiated.
    public static async Task<(Stream Stream, bool IsSecure)> NegotiateAsync(
        NetworkStream rawStream,
        string host,
        SslMode mode,
        bool trustServerCertificate,
        RemoteCertificateValidationCallback? userCallback,
        CancellationToken cancellationToken)
    {
        if (mode == SslMode.Disable)
            return (rawStream, false);

        // Send SSLRequest: Int32 length=8, Int32 code=80877103
        byte[] request = new byte[8];
        Helper.WriteInt32BE(request.AsSpan(0, 4), 8);
        Helper.WriteInt32BE(request.AsSpan(4, 4), SslRequestCode);
        await rawStream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

        byte[] response = new byte[1];
        await rawStream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);

        if (response[0] != (byte)'S')
        {
            if (mode is SslMode.Require or SslMode.VerifyCa or SslMode.VerifyFull)
                throw new InvalidOperationException(
                    $"Server rejected SSL but sslmode is {mode}.");

            return (rawStream, false);
        }

        RemoteCertificateValidationCallback validation = userCallback ?? BuildValidationCallback(mode, trustServerCertificate);
        var sslStream = new SslStream(rawStream, leaveInnerStreamOpen: false, validation);

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.None, // let OS pick TLS1.2+
            RemoteCertificateValidationCallback = validation,
        };

        await sslStream.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
        return (sslStream, true);
    }

    private static RemoteCertificateValidationCallback BuildValidationCallback(SslMode mode, bool trust)
    {
        return (sender, certificate, chain, sslPolicyErrors) =>
        {
            if (trust) return true;

            return mode switch
            {
                SslMode.Prefer or SslMode.Require => true, // no verification
                SslMode.VerifyCa =>
                    (sslPolicyErrors & ~SslPolicyErrors.RemoteCertificateNameMismatch) == SslPolicyErrors.None,
                SslMode.VerifyFull => sslPolicyErrors == SslPolicyErrors.None,
                _ => true,
            };
        };
    }
}
