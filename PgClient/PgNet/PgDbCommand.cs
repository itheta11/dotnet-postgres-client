using System.Data;
using System.Data.Common;
using PgClient.Query;

namespace PgClient.PgNet;

/// A <see cref="DbCommand"/> that executes SQL against a <see cref="PgDbConnection"/>.
///
/// If the parameter collection is empty the simple query protocol is used; if
/// any parameter is present the extended protocol (Parse/Bind/Describe/Execute/Sync)
/// is used and Postgres binds `$1..$N` positionally in declaration order.
public sealed class PgDbCommand : DbCommand
{
    private PgDbConnection? _connection;
    private PgDbTransaction? _transaction;
    private readonly PgDbParameterCollection _parameters = new();

    public PgDbCommand() { }
    public PgDbCommand(string commandText) { CommandText = commandText; }
    public PgDbCommand(string commandText, PgDbConnection connection)
    {
        CommandText = commandText;
        _connection = connection;
    }

    [System.Diagnostics.CodeAnalysis.AllowNull]
    public override string CommandText { get; set; } = string.Empty;
    public override int CommandTimeout { get; set; } = 30;
    public override CommandType CommandType { get; set; } = CommandType.Text;
    public override bool DesignTimeVisible { get; set; }
    public override UpdateRowSource UpdatedRowSource { get; set; } = UpdateRowSource.None;
    protected override DbConnection? DbConnection
    {
        get => _connection;
        set => _connection = (PgDbConnection?)value;
    }

    protected override DbParameterCollection DbParameterCollection => _parameters;

    protected override DbTransaction? DbTransaction
    {
        get => _transaction;
        set => _transaction = (PgDbTransaction?)value;
    }

    protected override DbParameter CreateDbParameter() => new PgDbParameter();

    public override void Cancel() => _connection?.NativeConnection?.CancelAsync().GetAwaiter().GetResult();

    public override int ExecuteNonQuery() => ExecuteNonQueryAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task<int> ExecuteNonQueryAsync(CancellationToken cancellationToken)
    {
        var native = RequireNativeConnection();
        Response.CommandTag tag;
        if (_parameters.Count == 0)
        {
            tag = await native.ExecuteNonQueryAsync(CommandText, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var list = ToPgParameters();
            tag = await native.ExecuteNonQueryAsync(CommandText, list, cancellationToken).ConfigureAwait(false);
        }
        return (int)tag.RowsAffected;
    }

    public override object? ExecuteScalar() => ExecuteScalarAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task<object?> ExecuteScalarAsync(CancellationToken cancellationToken)
    {
        var native = RequireNativeConnection();
        return _parameters.Count == 0
            ? await native.ExecuteScalarAsync(CommandText, cancellationToken).ConfigureAwait(false)
            : await native.ExecuteScalarAsync(CommandText, ToPgParameters(), cancellationToken).ConfigureAwait(false);
    }

    protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
        => ExecuteDbDataReaderAsync(behavior, CancellationToken.None).GetAwaiter().GetResult();

    protected override async Task<DbDataReader> ExecuteDbDataReaderAsync(CommandBehavior behavior, CancellationToken cancellationToken)
    {
        var native = RequireNativeConnection();
        var reader = _parameters.Count == 0
            ? await native.ExecuteReaderAsync(CommandText, cancellationToken).ConfigureAwait(false)
            : await native.ExecuteReaderAsync(CommandText, ToPgParameters(), cancellationToken).ConfigureAwait(false);
        return new PgDbDataReader(reader);
    }

    public override void Prepare() { /* auto-prepare handled by connection cache */ }

    private PgConnection RequireNativeConnection()
    {
        var conn = _connection ?? throw new InvalidOperationException("Command requires an open PgDbConnection.");
        return conn.NativeConnection ?? throw new InvalidOperationException("Connection is not open.");
    }

    private List<PgParameter> ToPgParameters()
    {
        var list = new List<PgParameter>(_parameters.Count);
        foreach (var p in _parameters.Items) list.Add(p.ToPgParameter());
        return list;
    }
}
