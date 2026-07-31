using System.Data;
using System.Data.Common;

namespace PgClient.PgNet;

/// A <see cref="DbConnection"/> that wraps the driver-native
/// <see cref="PgConnection"/>. Accepts a standard Npgsql-style connection string.
public sealed class PgDbConnection : DbConnection
{
    private string _connectionString = string.Empty;
    private PgConnection? _native;
    private ConnectionState _state = ConnectionState.Closed;
    private ConnectionParameters? _parsed;

    public PgDbConnection() { }
    public PgDbConnection(string connectionString) { ConnectionString = connectionString; }

    [System.Diagnostics.CodeAnalysis.AllowNull]
    public override string ConnectionString
    {
        get => _connectionString;
        set
        {
            _connectionString = value ?? string.Empty;
            _parsed = string.IsNullOrWhiteSpace(_connectionString)
                ? null
                : PgConnectionStringParser.Parse(_connectionString);
        }
    }

    public override string Database => _parsed?.Database ?? string.Empty;
    public override string DataSource => _parsed?.Hostname ?? string.Empty;
    public override string ServerVersion => _native?.ServerVersion ?? string.Empty;
    public override ConnectionState State => _state;

    /// The underlying driver-native connection. Null until <see cref="OpenAsync(CancellationToken)"/> completes.
    public PgConnection? NativeConnection => _native;

    public override void ChangeDatabase(string databaseName)
        => throw new NotSupportedException("Changing databases requires a new connection.");

    public override void Close()
    {
        if (_state == ConnectionState.Closed) return;
        var prev = _state;
        _native?.Close();
        _native?.Dispose();
        _native = null;
        _state = ConnectionState.Closed;
        OnStateChange(new StateChangeEventArgs(prev, ConnectionState.Closed));
    }

    public override void Open() => OpenAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task OpenAsync(CancellationToken cancellationToken)
    {
        if (_state == ConnectionState.Open) return;
        if (_parsed is null)
            throw new InvalidOperationException("ConnectionString has not been set.");

        _state = ConnectionState.Connecting;
        OnStateChange(new StateChangeEventArgs(ConnectionState.Closed, ConnectionState.Connecting));
        try
        {
            _native = new PgConnection(_parsed);
            await _native.ConnectAsync(cancellationToken).ConfigureAwait(false);
            _state = ConnectionState.Open;
            OnStateChange(new StateChangeEventArgs(ConnectionState.Connecting, ConnectionState.Open));
        }
        catch
        {
            _state = ConnectionState.Broken;
            throw;
        }
    }

    protected override DbCommand CreateDbCommand() => new PgDbCommand { Connection = this };

    protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
    {
        if (_native is null) throw new InvalidOperationException("Connection is not open.");
        var tx = _native.BeginTransactionAsync(isolationLevel).GetAwaiter().GetResult();
        return new PgDbTransaction(this, tx);
    }

    protected override async ValueTask<DbTransaction> BeginDbTransactionAsync(
        IsolationLevel isolationLevel, CancellationToken cancellationToken)
    {
        if (_native is null) throw new InvalidOperationException("Connection is not open.");
        var tx = await _native.BeginTransactionAsync(isolationLevel, cancellationToken).ConfigureAwait(false);
        return new PgDbTransaction(this, tx);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Close();
        base.Dispose(disposing);
    }
}
