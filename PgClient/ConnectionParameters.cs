using System.Net.Security;
using PgClient.Ssl;

namespace PgClient;

/// Everything needed to connect and pool a Postgres connection.
public sealed class ConnectionParameters
{
    public required string Hostname { get; set; }
    public required int Port { get; set; }
    public required string Database { get; set; }
    public required string Username { get; set; }

    public string Password { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public string FallbackApplicationName { get; set; } = string.Empty;

    // ── TLS ─────────────────────────────────────────────────────────────────

    public SslMode SslMode { get; set; } = SslMode.Prefer;

    /// If true, all certificate errors are ignored (equivalent to a permissive
    /// callback). Convenient for local dev; do not enable in production.
    public bool TrustServerCertificate { get; set; } = false;

    /// Optional user-supplied validation callback. When set it fully replaces
    /// the default policy derived from <see cref="SslMode"/>.
    public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

    // ── Pool ────────────────────────────────────────────────────────────────

    public int MinPoolSize { get; set; } = 0;
    public int MaxPoolSize { get; set; } = 100;
    public TimeSpan ConnectionIdleLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// Maximum lifetime for any pooled connection. Zero means unlimited.
    public TimeSpan ConnectionLifetime { get; set; } = TimeSpan.Zero;

    // ── Prepared statements ─────────────────────────────────────────────────

    /// Maximum number of automatically prepared statements per connection.
    /// Zero disables auto-preparation entirely.
    public int MaxAutoPrepare { get; set; } = 0;

    /// Number of usages required before a SQL is auto-prepared.
    public int AutoPrepareMinUsages { get; set; } = 5;

    // ── Timeouts ────────────────────────────────────────────────────────────

    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);
    public TimeSpan CommandTimeout { get; set; } = TimeSpan.FromSeconds(30);
}
