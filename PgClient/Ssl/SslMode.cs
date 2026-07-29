namespace PgClient.Ssl;

/// SSL/TLS negotiation mode; mirrors libpq's sslmode parameter.
public enum SslMode
{
    /// Never attempt TLS; plaintext only.
    Disable,

    /// Try TLS first; fall back to plaintext if the server refuses.
    Prefer,

    /// Require TLS; abort if the server refuses.
    Require,

    /// Require TLS and validate the server certificate chain (no hostname check).
    VerifyCa,

    /// Require TLS and validate certificate + hostname.
    VerifyFull,
}
