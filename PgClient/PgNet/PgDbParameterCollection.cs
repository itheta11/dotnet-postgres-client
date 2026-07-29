using System.Collections;
using System.Data.Common;

namespace PgClient.PgNet;

public sealed class PgDbParameterCollection : DbParameterCollection
{
    private readonly List<PgDbParameter> _items = new();

    public override int Count => _items.Count;
    public override object SyncRoot { get; } = new();

    public override int Add(object value)
    {
        _items.Add(Cast(value));
        return _items.Count - 1;
    }

    public override void AddRange(Array values)
    {
        foreach (var v in values) Add(v!);
    }

    public override void Clear() => _items.Clear();
    public override bool Contains(object value) => _items.Contains(Cast(value));
    public override bool Contains(string value) => IndexOf(value) >= 0;
    public override void CopyTo(Array array, int index) => ((ICollection)_items).CopyTo(array, index);
    public override IEnumerator GetEnumerator() => _items.GetEnumerator();

    public override int IndexOf(object value) => _items.IndexOf(Cast(value));
    public override int IndexOf(string parameterName)
    {
        for (int i = 0; i < _items.Count; i++)
            if (string.Equals(_items[i].ParameterName, parameterName, StringComparison.OrdinalIgnoreCase))
                return i;
        return -1;
    }

    public override void Insert(int index, object value) => _items.Insert(index, Cast(value));
    public override void Remove(object value) => _items.Remove(Cast(value));
    public override void RemoveAt(int index) => _items.RemoveAt(index);
    public override void RemoveAt(string parameterName)
    {
        int i = IndexOf(parameterName);
        if (i >= 0) _items.RemoveAt(i);
    }

    protected override DbParameter GetParameter(int index) => _items[index];
    protected override DbParameter GetParameter(string parameterName)
    {
        int i = IndexOf(parameterName);
        return i >= 0 ? _items[i] : throw new IndexOutOfRangeException(parameterName);
    }

    protected override void SetParameter(int index, DbParameter value) => _items[index] = Cast(value);
    protected override void SetParameter(string parameterName, DbParameter value)
    {
        int i = IndexOf(parameterName);
        if (i < 0) _items.Add(Cast(value));
        else _items[i] = Cast(value);
    }

    internal IReadOnlyList<PgDbParameter> Items => _items;

    private static PgDbParameter Cast(object value)
        => value as PgDbParameter
           ?? throw new InvalidCastException($"Expected PgDbParameter, got {value?.GetType()?.Name ?? "null"}.");
}
