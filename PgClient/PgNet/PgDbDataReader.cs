using System.Collections;
using System.Data;
using System.Data.Common;
using PgClient.Response;

namespace PgClient.PgNet;

/// A <see cref="DbDataReader"/> facade over the driver-native <see cref="PgDataReader"/>.
///
/// All accessors delegate to the underlying reader. Type-specific accessors are
/// implemented in terms of the reader's typed methods and fall back to
/// <see cref="Convert.ChangeType(object, Type)"/> when needed.
public sealed class PgDbDataReader : DbDataReader
{
    private readonly PgDataReader _inner;
    private bool _closed;

    internal PgDbDataReader(PgDataReader inner) { _inner = inner; }

    public override int FieldCount => _inner.FieldCount;
    public override object this[int ordinal] => GetValue(ordinal);
    public override object this[string name] => GetValue(GetOrdinal(name));
    public override int Depth => 0;
    public override bool HasRows => _inner.HasRows;
    public override bool IsClosed => _closed;
    public override int RecordsAffected => (int)_inner.CommandTag.RowsAffected;

    public override bool Read() => _inner.ReadAsync().AsTask().GetAwaiter().GetResult();
    public override Task<bool> ReadAsync(CancellationToken cancellationToken)
        => _inner.ReadAsync(cancellationToken).AsTask();

    public override bool NextResult() => false;
    public override Task<bool> NextResultAsync(CancellationToken cancellationToken) => Task.FromResult(false);

    public override string GetName(int ordinal) => _inner.GetName(ordinal);
    public override int GetOrdinal(string name)
    {
        for (int i = 0; i < _inner.FieldCount; i++)
            if (string.Equals(_inner.GetName(i), name, StringComparison.OrdinalIgnoreCase))
                return i;
        throw new IndexOutOfRangeException(name);
    }

    public override bool IsDBNull(int ordinal) => _inner.IsDBNull(ordinal);
    public override object GetValue(int ordinal) => _inner.GetValue(ordinal) ?? DBNull.Value;
    public override int GetValues(object[] values)
    {
        int n = Math.Min(values.Length, FieldCount);
        for (int i = 0; i < n; i++) values[i] = GetValue(i);
        return n;
    }

    public override bool GetBoolean(int ordinal) => _inner.GetBoolean(ordinal);
    public override byte GetByte(int ordinal) => (byte)_inner.GetInt16(ordinal);
    public override char GetChar(int ordinal) => _inner.GetString(ordinal)[0];
    public override DateTime GetDateTime(int ordinal) => _inner.GetDateTime(ordinal);
    public override decimal GetDecimal(int ordinal) => _inner.GetDecimal(ordinal);
    public override double GetDouble(int ordinal) => _inner.GetDouble(ordinal);
    public override float GetFloat(int ordinal) => _inner.GetFloat(ordinal);
    public override Guid GetGuid(int ordinal) => _inner.GetGuid(ordinal);
    public override short GetInt16(int ordinal) => _inner.GetInt16(ordinal);
    public override int GetInt32(int ordinal) => _inner.GetInt32(ordinal);
    public override long GetInt64(int ordinal) => _inner.GetInt64(ordinal);
    public override string GetString(int ordinal) => _inner.GetString(ordinal);

    public override long GetBytes(int ordinal, long dataOffset, byte[]? buffer, int bufferOffset, int length)
    {
        var src = _inner.GetBytes(ordinal);
        if (buffer is null) return src.Length;
        int take = Math.Min(length, src.Length - (int)dataOffset);
        src.Slice((int)dataOffset, take).CopyTo(buffer.AsSpan(bufferOffset));
        return take;
    }

    public override long GetChars(int ordinal, long dataOffset, char[]? buffer, int bufferOffset, int length)
    {
        var s = _inner.GetString(ordinal);
        if (buffer is null) return s.Length;
        int take = Math.Min(length, s.Length - (int)dataOffset);
        s.AsSpan((int)dataOffset, take).CopyTo(buffer.AsSpan(bufferOffset));
        return take;
    }

    public override string GetDataTypeName(int ordinal) => _inner.Columns[ordinal].TypeOid.ToString();
    public override Type GetFieldType(int ordinal)
    {
        var oid = _inner.Columns[ordinal].TypeOid;
        return Types.PgClrTypeFromOid(oid);
    }

    public override IEnumerator GetEnumerator() => new DbEnumerator(this, closeReader: false);

    public override void Close()
    {
        if (_closed) return;
        _closed = true;
        _inner.Dispose();
    }

    protected override void Dispose(bool disposing)
    {
        Close();
        base.Dispose(disposing);
    }
}
