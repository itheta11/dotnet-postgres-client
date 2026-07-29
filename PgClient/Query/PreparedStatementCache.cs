namespace PgClient.Query;

/// A tiny LRU cache that maps a SQL text to a server-side prepared statement name.
///
/// Not thread safe by itself — callers are expected to synchronize using the
/// owning connection's write lock (a connection is single-threaded).
public sealed class PreparedStatementCache
{
    private sealed class Entry
    {
        public required string StatementName;
        public int UseCount;
        public LinkedListNode<string>? LruNode;
    }

    private readonly int _maxSize;
    private readonly int _minUsagesBeforePrepare;
    private readonly Dictionary<string, Entry> _map;
    private readonly LinkedList<string> _lru = new();
    private int _nextId;

    public int Count => _map.Count;

    public PreparedStatementCache(int maxSize, int minUsagesBeforePrepare = 1)
    {
        _maxSize = Math.Max(0, maxSize);
        _minUsagesBeforePrepare = Math.Max(1, minUsagesBeforePrepare);
        _map = new Dictionary<string, Entry>(_maxSize == 0 ? 4 : _maxSize);
    }

    /// Records a use of the given SQL. Returns the statement name if the SQL is
    /// (or has just become) auto-prepared; returns null otherwise.
    /// When <paramref name="evicted"/> is non-null the caller should send a
    /// Close(Statement) message for that name.
    public string? TryGetOrPromote(string sql, out string? evicted)
    {
        evicted = null;
        if (_maxSize == 0) return null;

        if (_map.TryGetValue(sql, out var entry))
        {
            entry.UseCount++;
            if (entry.LruNode is not null)
            {
                _lru.Remove(entry.LruNode);
                entry.LruNode = _lru.AddFirst(sql);
            }
            return entry.StatementName;
        }

        // First-ever sighting: track usage count only, don't prepare yet.
        entry = new Entry { StatementName = string.Empty, UseCount = 1 };
        _map[sql] = entry;

        if (entry.UseCount >= _minUsagesBeforePrepare)
        {
            entry.StatementName = "_pg_auto_" + (++_nextId).ToString(System.Globalization.CultureInfo.InvariantCulture);
            entry.LruNode = _lru.AddFirst(sql);
            EvictIfNeeded(out evicted);
            return entry.StatementName;
        }

        return null;
    }

    /// Removes and returns every cached statement name (for connection teardown / DISCARD ALL).
    public IEnumerable<string> Drain()
    {
        foreach (var kv in _map)
        {
            if (!string.IsNullOrEmpty(kv.Value.StatementName))
                yield return kv.Value.StatementName;
        }
        _map.Clear();
        _lru.Clear();
    }

    private void EvictIfNeeded(out string? evictedStatementName)
    {
        evictedStatementName = null;
        while (_map.Count > _maxSize && _lru.Last is not null)
        {
            string oldest = _lru.Last.Value;
            _lru.RemoveLast();
            if (_map.TryGetValue(oldest, out var entry))
            {
                evictedStatementName = entry.StatementName;
                _map.Remove(oldest);
            }
        }
    }
}
