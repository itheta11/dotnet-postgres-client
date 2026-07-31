using System.Diagnostics.Metrics;
using System.Reflection;

namespace PgClient.Diagnostics;

/// Shared <see cref="Meter"/> and instrument definitions for the PgClient library.
/// Instruments follow OpenTelemetry semantic conventions where practical.
public static class PgClientMetrics
{
    /// <summary>Meter name — subscribe to this to consume PgClient metrics.</summary>
    public const string MeterName = "PgClient";

    /// <summary>Version of the meter, sourced from the assembly's informational version.</summary>
    public static string MeterVersion { get; } =
        typeof(PgClientMetrics).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "0.0.0";

    /// <summary>The shared meter used by the library.</summary>
    public static Meter Meter { get; } = new(MeterName, MeterVersion);

    // ── Instruments ─────────────────────────────────────────────────────────

    /// <summary>Total number of commands executed.</summary>
    public static readonly Counter<long> CommandsExecuted =
        Meter.CreateCounter<long>("pgclient.commands_total", unit: "{commands}", description: "Total commands executed");

    /// <summary>Total number of command failures.</summary>
    public static readonly Counter<long> CommandsFailed =
        Meter.CreateCounter<long>("pgclient.commands_failed_total", unit: "{commands}", description: "Total commands that raised an exception");

    /// <summary>Duration of command execution in milliseconds.</summary>
    public static readonly Histogram<double> CommandDurationMs =
        Meter.CreateHistogram<double>("pgclient.command_duration", unit: "ms", description: "Duration of a single command");

    /// <summary>Total connections opened over the socket layer.</summary>
    public static readonly Counter<long> ConnectionsOpened =
        Meter.CreateCounter<long>("pgclient.connections_opened_total", unit: "{connections}", description: "Physical connections opened");

    /// <summary>Total connections closed.</summary>
    public static readonly Counter<long> ConnectionsClosed =
        Meter.CreateCounter<long>("pgclient.connections_closed_total", unit: "{connections}", description: "Physical connections closed");

    /// <summary>Total pool rents (a rent may reuse an idle connection).</summary>
    public static readonly Counter<long> PoolRents =
        Meter.CreateCounter<long>("pgclient.pool_rents_total", unit: "{rents}", description: "Pool rent operations");

    /// <summary>Total pool waits that had to block for an available slot.</summary>
    public static readonly Counter<long> PoolWaits =
        Meter.CreateCounter<long>("pgclient.pool_waits_total", unit: "{waits}", description: "Pool rents that had to wait for a slot");

    /// <summary>Total pool rent timeouts.</summary>
    public static readonly Counter<long> PoolTimeouts =
        Meter.CreateCounter<long>("pgclient.pool_timeouts_total", unit: "{timeouts}", description: "Pool rents that timed out waiting for a slot");
}
