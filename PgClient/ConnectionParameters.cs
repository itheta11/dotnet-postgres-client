using System.Diagnostics.Metrics;
using System.Net.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PgClient.Ssl;

namespace PgClient;

/// Everything needed to connect and pool a Postgres connection.
public sealed class ConnectionParameters
{
    /// <summary>Hostname or IP of the Postgres server.</summary>
    public required string Hostname { get; set; }

    /// <summary>TCP port. The Postgres default is 5432.</summary>
    public required int Port { get; set; }

    /// <summary>Target database name.</summary>
    public required string Database { get; set; }

    /// <summary>Postgres role to authenticate as.</summary>
    public required string Username { get; set; }

    /// <summary>Password used for authentication. Redacted from <see cref="ToString"/>.</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>Value of the <c>application_name</c> startup parameter.</summary>
    public string ApplicationName { get; set; } = string.Empty;

    /// <summary>Fallback application name (currently informational).</summary>
    public string FallbackApplicationName { get; set; } = string.Empty;

    // ── TLS ─────────────────────────────────────────────────────────────────

    /// <summary>How to negotiate TLS with the server.</summary>
    public SslMode SslMode { get; set; } = SslMode.Prefer;

    /// <summary>
    /// When true, all certificate errors are ignored. Convenient for local dev
    /// only; do not enable in production.
    /// </summary>
    public bool TrustServerCertificate { get; set; }

    /// <summary>
    /// Optional user-supplied validation callback. When set it fully replaces
    /// the default policy derived from <see cref="SslMode"/>.
    /// </summary>
    public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

    // ── Pool ────────────────────────────────────────────────────────────────

    /// <summary>Minimum number of pooled connections to keep open.</summary>
    public int MinPoolSize { get; set; }

    /// <summary>Maximum number of pooled connections. Must be at least 1.</summary>
    public int MaxPoolSize { get; set; } = 100;

    /// <summary>Idle time before a pooled connection is closed by pruning.</summary>
    public TimeSpan ConnectionIdleLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Maximum lifetime for any pooled connection. Zero means unlimited.</summary>
    public TimeSpan ConnectionLifetime { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Maximum time <c>PgConnectionPool.RentAsync</c> will wait for a slot
    /// when the pool is exhausted. Zero means unlimited.
    /// </summary>
    public TimeSpan PoolWaitTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// When true, the pool skips <c>DISCARD ALL</c> on return. Recommended when
    /// running behind a proxy such as PgBouncer in transaction pooling mode, or
    /// when the caller manages session state explicitly.
    /// </summary>
    public bool NoResetOnClose { get; set; }

    // ── Prepared statements ─────────────────────────────────────────────────

    /// <summary>Maximum number of automatically prepared statements per connection. Zero disables auto-prepare.</summary>
    public int MaxAutoPrepare { get; set; }

    /// <summary>Number of usages before a SQL string is auto-prepared.</summary>
    public int AutoPrepareMinUsages { get; set; } = 5;

    // ── Timeouts ────────────────────────────────────────────────────────────

    /// <summary>Time allowed for the initial TCP + startup handshake.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Per-command timeout applied automatically inside execute methods. Zero disables.</summary>
    public TimeSpan CommandTimeout { get; set; } = TimeSpan.FromSeconds(30);

    // ── TCP keepalive ───────────────────────────────────────────────────────

    /// <summary>Enable TCP keepalive on the underlying socket.</summary>
    public bool TcpKeepAlive { get; set; } = true;

    /// <summary>Idle time before the first keepalive probe is sent.</summary>
    public TimeSpan TcpKeepAliveTime { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Interval between subsequent keepalive probes.</summary>
    public TimeSpan TcpKeepAliveInterval { get; set; } = TimeSpan.FromSeconds(10);

    // ── Diagnostics ─────────────────────────────────────────────────────────

    /// <summary>Optional logger factory. When null, logging is disabled.</summary>
    public ILoggerFactory? LoggerFactory { get; set; }

    /// <summary>Optional custom meter. When null, the shared PgClient meter is used.</summary>
    public Meter? Meter { get; set; }

    internal ILogger GetLogger(string category)
        => (LoggerFactory ?? NullLoggerFactory.Instance).CreateLogger(category);

    /// <summary>Returns a diagnostic string with the password redacted.</summary>
    public override string ToString()
    {
        var pwd = string.IsNullOrEmpty(Password) ? "" : "***";
        return $"Host={Hostname};Port={Port};Username={Username};Database={Database};"
             + $"Password={pwd};SslMode={SslMode};ApplicationName={ApplicationName};"
             + $"Pool=[{MinPoolSize}..{MaxPoolSize}];CommandTimeout={CommandTimeout};ConnectTimeout={ConnectTimeout}";
    }
}
