using System.Data;
using System.Data.Common;

namespace PgClient.PgNet;

/// A <see cref="DbTransaction"/> that delegates to the driver-native <see cref="PgTransaction"/>.
public sealed class PgDbTransaction : DbTransaction
{
    private readonly PgDbConnection _connection;
    private readonly PgTransaction _inner;
    private bool _completed;

    internal PgDbTransaction(PgDbConnection connection, PgTransaction inner)
    {
        _connection = connection;
        _inner = inner;
    }

    protected override DbConnection DbConnection => _connection;
    public override IsolationLevel IsolationLevel => _inner.IsolationLevel;

    public override void Commit() => _inner.CommitAsync().GetAwaiter().GetResult();
    public override Task CommitAsync(CancellationToken cancellationToken = default) => _inner.CommitAsync(cancellationToken);

    public override void Rollback() => _inner.RollbackAsync().GetAwaiter().GetResult();
    public override Task RollbackAsync(CancellationToken cancellationToken = default) => _inner.RollbackAsync(cancellationToken);

    public override bool SupportsSavepoints => true;
    public override void Save(string savepointName) => _inner.SaveAsync(savepointName).GetAwaiter().GetResult();
    public override void Rollback(string savepointName) => _inner.RollbackAsync(savepointName).GetAwaiter().GetResult();
    public override void Release(string savepointName) => _inner.ReleaseAsync(savepointName).GetAwaiter().GetResult();

    protected override void Dispose(bool disposing)
    {
        if (_completed) return;
        _completed = true;
        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }
}
