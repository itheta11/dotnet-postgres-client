using System.Data;
using PgClient.Response;

namespace PgClient;

/// A logical Postgres transaction over a <see cref="PgConnection"/>.
///
/// Wraps the standard <c>BEGIN</c>/<c>COMMIT</c>/<c>ROLLBACK</c> commands and
/// tracks savepoints. Rolling back a savepoint discards it. Committing or
/// rolling back the outer transaction disposes the object.
public sealed class PgTransaction : IAsyncDisposable, IDisposable
{
    private readonly PgConnection _connection;
    private readonly Stack<string> _savepoints = new();
    private bool _completed;

    public IsolationLevel IsolationLevel { get; }
    public PgConnection Connection => _connection;

    internal PgTransaction(PgConnection connection, IsolationLevel isolation)
    {
        _connection = connection;
        IsolationLevel = isolation;
    }

    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        EnsureActive();
        await _connection.ExecuteNonQueryAsync("COMMIT", cancellationToken).ConfigureAwait(false);
        _completed = true;
    }

    public async Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        EnsureActive();
        await _connection.ExecuteNonQueryAsync("ROLLBACK", cancellationToken).ConfigureAwait(false);
        _completed = true;
    }

    public async Task SaveAsync(string name, CancellationToken cancellationToken = default)
    {
        EnsureActive();
        ValidateSavepointName(name);
        await _connection.ExecuteNonQueryAsync($"SAVEPOINT \"{name}\"", cancellationToken).ConfigureAwait(false);
        _savepoints.Push(name);
    }

    public async Task RollbackAsync(string savepointName, CancellationToken cancellationToken = default)
    {
        EnsureActive();
        ValidateSavepointName(savepointName);
        await _connection.ExecuteNonQueryAsync(
            $"ROLLBACK TO SAVEPOINT \"{savepointName}\"", cancellationToken).ConfigureAwait(false);
    }

    public async Task ReleaseAsync(string savepointName, CancellationToken cancellationToken = default)
    {
        EnsureActive();
        ValidateSavepointName(savepointName);
        await _connection.ExecuteNonQueryAsync(
            $"RELEASE SAVEPOINT \"{savepointName}\"", cancellationToken).ConfigureAwait(false);
    }

    private void EnsureActive()
    {
        if (_completed) throw new InvalidOperationException("Transaction has already been completed.");
    }

    private static void ValidateSavepointName(string name)
    {
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Savepoint name is required.", nameof(name));
        foreach (var c in name)
        {
            if (c == '"' || c == '\0')
                throw new ArgumentException("Savepoint name contains invalid characters.", nameof(name));
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_completed) return;
        try { await RollbackAsync().ConfigureAwait(false); }
        catch { /* connection may already be broken */ }
    }

    public void Dispose()
    {
        if (_completed) return;
        try { _connection.ExecuteNonQueryAsync("ROLLBACK").GetAwaiter().GetResult(); }
        catch { /* swallow */ }
        _completed = true;
    }
}
