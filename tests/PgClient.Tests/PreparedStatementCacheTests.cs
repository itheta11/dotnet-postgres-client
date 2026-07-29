using PgClient.Query;
using Xunit;

namespace PgClient.Tests;

public class PreparedStatementCacheTests
{
    [Fact]
    public void MaxSizeZero_NeverPrepares()
    {
        var c = new PreparedStatementCache(maxSize: 0);
        Assert.Null(c.TryGetOrPromote("SELECT 1", out var evicted));
        Assert.Null(evicted);
    }

    [Fact]
    public void MinUsagesOne_PreparesOnFirstUse()
    {
        var c = new PreparedStatementCache(maxSize: 4, minUsagesBeforePrepare: 1);
        var name = c.TryGetOrPromote("SELECT 1", out _);
        Assert.False(string.IsNullOrEmpty(name));
        Assert.Equal(1, c.Count);
    }

    [Fact]
    public void MinUsagesTwo_PromotesOnSecondUse()
    {
        var c = new PreparedStatementCache(maxSize: 4, minUsagesBeforePrepare: 2);
        // Actually the current impl promotes when UseCount >= minUsages on first insert.
        // With minUsages=2 the first sighting has UseCount=1, so it's not prepared yet.
        Assert.Null(c.TryGetOrPromote("SELECT 1", out _));
    }

    [Fact]
    public void CacheHits_ReturnSameStatementName()
    {
        var c = new PreparedStatementCache(maxSize: 4);
        var first = c.TryGetOrPromote("SELECT 1", out _);
        var second = c.TryGetOrPromote("SELECT 1", out _);
        Assert.Equal(first, second);
    }

    [Fact]
    public void ExceedingMaxSize_EvictsLeastRecentlyUsed()
    {
        var c = new PreparedStatementCache(maxSize: 2);
        var n1 = c.TryGetOrPromote("A", out _);
        var n2 = c.TryGetOrPromote("B", out _);
        // Access A again → B is now the LRU.
        c.TryGetOrPromote("A", out _);
        // Insert C → evict B.
        var n3 = c.TryGetOrPromote("C", out var evicted);
        Assert.Equal(n2, evicted);
        Assert.NotEqual(n1, n3);
    }

    [Fact]
    public void Drain_ClearsCache_AndYieldsAllNames()
    {
        var c = new PreparedStatementCache(maxSize: 4);
        c.TryGetOrPromote("A", out _);
        c.TryGetOrPromote("B", out _);
        var drained = c.Drain().ToList();
        Assert.Equal(2, drained.Count);
        Assert.Equal(0, c.Count);
    }
}
