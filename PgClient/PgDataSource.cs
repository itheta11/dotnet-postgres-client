using PgClient.Pool;

namespace PgClient;

/// The primary factory for pooled Postgres connections. Create a single
/// <see cref="PgDataSource"/> per application per (host, port, user, database)
/// combination and share it — connection pooling and shared type registration
/// happen behind this facade.
public sealed class PgDataSource : IAsyncDisposable
{
    private readonly ConnectionParameters _parameters;
    private readonly PgConnectionPool _pool;
    private int _disposed;

    public PgDataSource(ConnectionParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        _pool = new PgConnectionPool(_parameters);
    }

    /// Rents a connection from the pool. The returned connection returns to the
    /// pool when disposed.
    public ValueTask<PgConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
        => _pool.RentAsync(cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        await _pool.DisposeAsync().ConfigureAwait(false);
    }
}
