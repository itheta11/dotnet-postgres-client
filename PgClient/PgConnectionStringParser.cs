using System.Globalization;
using PgClient.Ssl;

namespace PgClient;

/// Parses Npgsql-compatible connection strings into <see cref="ConnectionParameters"/>.
///
/// Accepted keys (case-insensitive, aliases supported):
///   Host / Server            — hostname
///   Port                     — TCP port (default 5432)
///   Username / User Id       — Postgres role
///   Password                 — password
///   Database                 — database name
///   Application Name         — application_name startup parameter
///   SSL Mode / SslMode       — Disable | Prefer | Require | VerifyCa | VerifyFull
///   Trust Server Certificate — true / false
///   Timeout                  — connect timeout, seconds
///   Command Timeout          — per-command timeout, seconds
///   Maximum Pool Size        — max pooled connections (default 100)
///   Minimum Pool Size        — min pooled connections
///   Connection Idle Lifetime — seconds an idle connection lives in the pool
///   Connection Lifetime      — max total lifetime in seconds (0 = unlimited)
///   Max Auto Prepare         — max auto-prepared statements per connection
///   Auto Prepare Min Usages  — usages before auto-prepare kicks in
///
/// Whitespace around keys and values is trimmed. Values containing ';' or '='
/// must be wrapped in single or double quotes.
public static class PgConnectionStringParser
{
    public static ConnectionParameters Parse(string connectionString)
    {
        ArgumentNullException.ThrowIfNull(connectionString);

        var kv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int i = 0;
        while (i < connectionString.Length)
        {
            // skip whitespace
            while (i < connectionString.Length && char.IsWhiteSpace(connectionString[i])) i++;
            if (i >= connectionString.Length) break;

            int keyStart = i;
            while (i < connectionString.Length && connectionString[i] != '=') i++;
            if (i >= connectionString.Length)
                throw new FormatException("Connection string is missing '=' after a key.");

            string key = connectionString.Substring(keyStart, i - keyStart).Trim();
            i++; // consume '='

            while (i < connectionString.Length && char.IsWhiteSpace(connectionString[i])) i++;

            string value;
            if (i < connectionString.Length && (connectionString[i] == '"' || connectionString[i] == '\''))
            {
                char quote = connectionString[i++];
                int valStart = i;
                while (i < connectionString.Length && connectionString[i] != quote) i++;
                if (i >= connectionString.Length)
                    throw new FormatException($"Unterminated {quote}-quoted value in connection string.");
                value = connectionString.Substring(valStart, i - valStart);
                i++; // consume closing quote
                // skip trailing whitespace + optional ';'
                while (i < connectionString.Length && char.IsWhiteSpace(connectionString[i])) i++;
                if (i < connectionString.Length && connectionString[i] == ';') i++;
            }
            else
            {
                int valStart = i;
                while (i < connectionString.Length && connectionString[i] != ';') i++;
                value = connectionString.Substring(valStart, i - valStart).Trim();
                if (i < connectionString.Length && connectionString[i] == ';') i++;
            }

            if (key.Length == 0)
                throw new FormatException("Empty key in connection string.");
            kv[NormalizeKey(key)] = value;
        }

        return Build(kv);
    }

    private static ConnectionParameters Build(Dictionary<string, string> kv)
    {
        string host = Require(kv, "host");
        int port = TryGet(kv, "port", out var p) ? int.Parse(p, CultureInfo.InvariantCulture) : 5432;
        string user = Require(kv, "username");
        string db = Require(kv, "database");

        var cp = new ConnectionParameters
        {
            Hostname = host,
            Port = port,
            Username = user,
            Database = db,
        };

        if (TryGet(kv, "password", out var pwd)) cp.Password = pwd;
        if (TryGet(kv, "applicationname", out var app)) cp.ApplicationName = app;
        if (TryGet(kv, "fallbackapplicationname", out var fallback)) cp.FallbackApplicationName = fallback;

        if (TryGet(kv, "sslmode", out var ssl))
            cp.SslMode = ParseSslMode(ssl);
        if (TryGet(kv, "trustservercertificate", out var trust))
            cp.TrustServerCertificate = ParseBool(trust);

        if (TryGet(kv, "timeout", out var to))
            cp.ConnectTimeout = TimeSpan.FromSeconds(double.Parse(to, CultureInfo.InvariantCulture));
        if (TryGet(kv, "commandtimeout", out var cto))
            cp.CommandTimeout = TimeSpan.FromSeconds(double.Parse(cto, CultureInfo.InvariantCulture));

        if (TryGet(kv, "maximumpoolsize", out var max))
            cp.MaxPoolSize = int.Parse(max, CultureInfo.InvariantCulture);
        if (TryGet(kv, "minimumpoolsize", out var min))
            cp.MinPoolSize = int.Parse(min, CultureInfo.InvariantCulture);
        if (TryGet(kv, "connectionidlelifetime", out var idle))
            cp.ConnectionIdleLifetime = TimeSpan.FromSeconds(double.Parse(idle, CultureInfo.InvariantCulture));
        if (TryGet(kv, "connectionlifetime", out var life))
            cp.ConnectionLifetime = TimeSpan.FromSeconds(double.Parse(life, CultureInfo.InvariantCulture));

        if (TryGet(kv, "maxautoprepare", out var map))
            cp.MaxAutoPrepare = int.Parse(map, CultureInfo.InvariantCulture);
        if (TryGet(kv, "autopreparemin usages", out var apu) || TryGet(kv, "autopreparemin", out apu))
            cp.AutoPrepareMinUsages = int.Parse(apu, CultureInfo.InvariantCulture);

        return cp;
    }

    /// Serialises a <see cref="ConnectionParameters"/> back to a canonical connection string.
    /// The password is included only if <paramref name="includePassword"/> is true.
    public static string ToConnectionString(ConnectionParameters p, bool includePassword = false)
    {
        var sb = new System.Text.StringBuilder();
        Append(sb, "Host", p.Hostname);
        Append(sb, "Port", p.Port.ToString(CultureInfo.InvariantCulture));
        Append(sb, "Username", p.Username);
        Append(sb, "Database", p.Database);
        if (includePassword && !string.IsNullOrEmpty(p.Password)) Append(sb, "Password", p.Password);
        if (!string.IsNullOrEmpty(p.ApplicationName)) Append(sb, "Application Name", p.ApplicationName);
        Append(sb, "SSL Mode", p.SslMode.ToString());
        if (p.TrustServerCertificate) Append(sb, "Trust Server Certificate", "true");
        Append(sb, "Maximum Pool Size", p.MaxPoolSize.ToString(CultureInfo.InvariantCulture));
        if (p.MinPoolSize > 0) Append(sb, "Minimum Pool Size", p.MinPoolSize.ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static void Append(System.Text.StringBuilder sb, string key, string value)
    {
        if (sb.Length > 0) sb.Append(';');
        sb.Append(key).Append('=');
        if (value.IndexOfAny(new[] { ';', '=', '"' }) >= 0)
            sb.Append('"').Append(value.Replace("\"", "\"\"")).Append('"');
        else
            sb.Append(value);
    }

    private static string Require(Dictionary<string, string> kv, string key)
        => TryGet(kv, key, out var v)
            ? v
            : throw new FormatException($"Connection string is missing required key '{key}'.");

    private static bool TryGet(Dictionary<string, string> kv, string normalisedKey, out string value)
        => kv.TryGetValue(normalisedKey, out value!);

    private static string NormalizeKey(string key)
    {
        // Strip spaces, dashes, underscores for lookup: "SSL Mode" == "SslMode" == "ssl_mode".
        string k = key.Replace(" ", "").Replace("-", "").Replace("_", "").ToLowerInvariant();
        return k switch
        {
            "server" or "hostname" => "host",
            "userid" or "user" or "uid" => "username",
            "db" => "database",
            "pwd" => "password",
            "sslmode" => "sslmode",
            "trustservercertificate" => "trustservercertificate",
            _ => k,
        };
    }

    private static SslMode ParseSslMode(string value) => value.ToLowerInvariant() switch
    {
        "disable" or "off" => SslMode.Disable,
        "prefer" => SslMode.Prefer,
        "require" => SslMode.Require,
        "verifyca" or "verify-ca" => SslMode.VerifyCa,
        "verifyfull" or "verify-full" => SslMode.VerifyFull,
        _ => throw new FormatException($"Unknown SSL Mode '{value}'."),
    };

    private static bool ParseBool(string value)
    {
        if (bool.TryParse(value, out var b)) return b;
        return value.ToLowerInvariant() switch
        {
            "1" or "yes" or "on" => true,
            "0" or "no" or "off" => false,
            _ => throw new FormatException($"Cannot parse '{value}' as boolean."),
        };
    }
}
