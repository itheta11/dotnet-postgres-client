using System.Collections.Concurrent;

namespace PgClient.Pool;

/// A minimal, high-throughput connection pool.
///
/// - Idle connections live on a lock-free stack (LIFO) to keep hot connections hot.
/// - Total open count is capped by a <see cref="SemaphoreSlim"/>.
/// - Idle connections older than <see cref="ConnectionParameters.ConnectionIdleLifetime"/>
///   are pruned lazily on Rent / periodically on a background timer.
public sealed class PgConnectionPool : IAsyncDisposable
{
    private readonly ConnectionParameters _parameters;
    private readonly SemaphoreSlim _sizeGate;
    private readonly ConcurrentStack<Slot> _idle = new();
    private readonly Timer? _pruneTimer;
    private volatile bool _disposed;

    public int MaxPoolSize { get; }
    public int MinPoolSize { get; }
    public TimeSpan IdleLifetime { get; }
    public TimeSpan MaxLifetime { get; }

    public PgConnectionPool(ConnectionParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        MaxPoolSize = Math.Max(1, parameters.MaxPoolSize);
        MinPoolSize = Math.Clamp(parameters.MinPoolSize, 0, MaxPoolSize);
        IdleLifetime = parameters.ConnectionIdleLifetime;
        MaxLifetime = parameters.ConnectionLifetime;

        _sizeGate = new SemaphoreSlim(MaxPoolSize, MaxPoolSize);

        if (IdleLifetime > TimeSpan.Zero)
        {
            _pruneTimer = new Timer(_ => Prune(), null,
                IdleLifetime, IdleLifetime);
        }
    }

    public async ValueTask<PgConnection> RentAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        while (_idle.TryPop(out var slot))
        {
            if (IsExpired(slot))
            {
                DisposeSlot(slot);
                continue;
            }
            slot.Connection.MarkRented();
            return slot.Connection;
        }

        await _sizeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var conn = new PgConnection(_parameters) { Pool = this };
            await conn.ConnectAsync(cancellationToken).ConfigureAwait(false);
            conn.MarkRented();
            return conn;
        }
        catch
        {
            _sizeGate.Release();
            throw;
        }
    }

    internal void Return(PgConnection connection)
    {
        if (_disposed || connection.IsBroken)
        {
            connection.CloseInternal();
            _sizeGate.Release();
            return;
        }

        connection.MarkIdle();
        _idle.Push(new Slot(connection, DateTime.UtcNow));
    }

    private void Prune()
    {
        if (_disposed) return;

        var kept = new List<Slot>();
        while (_idle.TryPop(out var s))
        {
            if (IsExpired(s)) DisposeSlot(s);
            else kept.Add(s);
        }
        foreach (var s in kept) _idle.Push(s);
    }

    private bool IsExpired(Slot slot)
    {
        var now = DateTime.UtcNow;
        if (IdleLifetime > TimeSpan.Zero && now - slot.IdleSince > IdleLifetime) return true;
        if (MaxLifetime > TimeSpan.Zero && now - slot.Connection.OpenedAtUtc > MaxLifetime) return true;
        return slot.Connection.IsBroken;
    }

    private void DisposeSlot(Slot slot)
    {
        try { slot.Connection.CloseInternal(); } catch { /* swallow */ }
        _sizeGate.Release();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (_pruneTimer is not null) await _pruneTimer.DisposeAsync().ConfigureAwait(false);

        while (_idle.TryPop(out var slot)) DisposeSlot(slot);
        _sizeGate.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(PgConnectionPool));
    }

    private readonly record struct Slot(PgConnection Connection, DateTime IdleSince);
}
