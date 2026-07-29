using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using PgClient.BufferUtils;
using PgClient.Protocol;

namespace PgClient.Response;

/// Forward-only, streaming reader over a Postgres query result set.
/// Values are held as raw text-format bytes and decoded lazily via typed accessors.
/// The reader MUST be fully consumed or disposed so the connection state can be
/// restored to ReadyForQuery before the next command is issued.
public sealed class PgDataReader : IAsyncDisposable, IDisposable
{
    private readonly Stream _stream;
    private readonly BufferStreamReader _protocol;
    private readonly Action<PostgresProtocol.TransactionStatus>? _onReadyForQuery;
    private readonly Action<PgErrorInfo>? _onNotice;
    private readonly Action<ReadOnlyMemory<byte>>? _onParameterStatus;
    private readonly Action<int, string, string>? _onNotification;

    private FieldDescription[] _columns = Array.Empty<FieldDescription>();
    private byte[]?[] _currentRow = Array.Empty<byte[]?>();
    private bool _hasRow;
    private bool _resultSetExhausted;
    private bool _disposed;

    private CommandTag _lastTag = CommandTag.Empty;

    internal PgDataReader(
        Stream stream,
        BufferStreamReader protocol,
        Action<PostgresProtocol.TransactionStatus>? onReadyForQuery = null,
        Action<PgErrorInfo>? onNotice = null,
        Action<ReadOnlyMemory<byte>>? onParameterStatus = null,
        Action<int, string, string>? onNotification = null)
    {
        _stream = stream;
        _protocol = protocol;
        _onReadyForQuery = onReadyForQuery;
        _onNotice = onNotice;
        _onParameterStatus = onParameterStatus;
        _onNotification = onNotification;
    }

    public int FieldCount => _columns.Length;
    public IReadOnlyList<FieldDescription> Columns => _columns;
    public CommandTag CommandTag => _lastTag;
    public bool HasRows => _hasRow || !_resultSetExhausted;

    /// Advances to the next data row. Returns false when the current result set ends.
    public async ValueTask<bool> ReadAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_resultSetExhausted) return false;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (code, payload) = await _protocol.ReadQueryMessageAsync(_stream).ConfigureAwait(false);

            switch ((PostgresProtocol.BackendMessageCode)code)
            {
                case PostgresProtocol.BackendMessageCode.RowDescription:
                    _columns = ParseRowDescription(payload);
                    _currentRow = new byte[]?[_columns.Length];
                    break;

                case PostgresProtocol.BackendMessageCode.DataRow:
                    ParseDataRow(payload);
                    _hasRow = true;
                    return true;

                case PostgresProtocol.BackendMessageCode.CommandComplete:
                    _lastTag = CommandTag.Parse(payload);
                    _hasRow = false;
                    break;

                case PostgresProtocol.BackendMessageCode.EmptyQueryResponse:
                    _lastTag = CommandTag.Empty;
                    _hasRow = false;
                    break;

                case PostgresProtocol.BackendMessageCode.NoticeResponse:
                    _onNotice?.Invoke(PgErrorInfo.Parse(payload));
                    break;

                case PostgresProtocol.BackendMessageCode.ParameterStatus:
                    _onParameterStatus?.Invoke(payload);
                    break;

                case PostgresProtocol.BackendMessageCode.NotificationResponse:
                    ParseAndDispatchNotification(payload);
                    break;

                case PostgresProtocol.BackendMessageCode.ErrorResponse:
                    var info = PgErrorInfo.Parse(payload);
                    // Drain until ReadyForQuery so the connection is usable.
                    await DrainToReadyForQueryAsync(cancellationToken).ConfigureAwait(false);
                    throw new PgException(info);

                case PostgresProtocol.BackendMessageCode.ReadyForQuery:
                    HandleReadyForQuery(payload);
                    _resultSetExhausted = true;
                    return false;

                case PostgresProtocol.BackendMessageCode.PortalSuspended:
                case PostgresProtocol.BackendMessageCode.NoData:
                    break;

                default:
                    // Unknown message: ignore to keep the stream aligned.
                    break;
            }
        }
    }

    private async ValueTask DrainToReadyForQueryAsync(CancellationToken ct)
    {
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var (code, payload) = await _protocol.ReadQueryMessageAsync(_stream).ConfigureAwait(false);
            if ((PostgresProtocol.BackendMessageCode)code == PostgresProtocol.BackendMessageCode.ReadyForQuery)
            {
                HandleReadyForQuery(payload);
                _resultSetExhausted = true;
                return;
            }
        }
    }

    private void HandleReadyForQuery(byte[] payload)
    {
        if (payload.Length >= 1)
        {
            var status = (PostgresProtocol.TransactionStatus)payload[0];
            _onReadyForQuery?.Invoke(status);
        }
    }

    private void ParseAndDispatchNotification(byte[] payload)
    {
        if (_onNotification is null) return;
        var span = payload.AsSpan();
        int pid = BinaryPrimitives.ReadInt32BigEndian(span);
        int i = 4;
        int nul = span.Slice(i).IndexOf((byte)0);
        string channel = Encoding.UTF8.GetString(span.Slice(i, nul));
        i += nul + 1;
        nul = span.Slice(i).IndexOf((byte)0);
        string message = Encoding.UTF8.GetString(span.Slice(i, nul));
        _onNotification(pid, channel, message);
    }

    private static FieldDescription[] ParseRowDescription(byte[] payload)
    {
        var span = payload.AsSpan();
        short fieldCount = BinaryPrimitives.ReadInt16BigEndian(span);
        var result = new FieldDescription[fieldCount];
        int offset = 2;

        for (int i = 0; i < fieldCount; i++)
        {
            int nameEnd = span.Slice(offset).IndexOf((byte)0);
            if (nameEnd < 0) throw new InvalidDataException("Unterminated column name.");
            string name = Encoding.UTF8.GetString(span.Slice(offset, nameEnd));
            offset += nameEnd + 1;

            uint tableOid = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(offset, 4)); offset += 4;
            short columnAttr = BinaryPrimitives.ReadInt16BigEndian(span.Slice(offset, 2)); offset += 2;
            uint typeOid = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(offset, 4)); offset += 4;
            short typeSize = BinaryPrimitives.ReadInt16BigEndian(span.Slice(offset, 2)); offset += 2;
            int typeMod = BinaryPrimitives.ReadInt32BigEndian(span.Slice(offset, 4)); offset += 4;
            short format = BinaryPrimitives.ReadInt16BigEndian(span.Slice(offset, 2)); offset += 2;

            result[i] = new FieldDescription
            {
                Name = name,
                TableOid = tableOid,
                ColumnAttributeNumber = columnAttr,
                TypeOid = typeOid,
                TypeSize = typeSize,
                TypeModifier = typeMod,
                FormatCode = (PgFormatCode)format,
            };
        }
        return result;
    }

    private void ParseDataRow(byte[] payload)
    {
        var span = payload.AsSpan();
        short fieldCount = BinaryPrimitives.ReadInt16BigEndian(span);
        if (fieldCount != _currentRow.Length)
            _currentRow = new byte[]?[fieldCount];

        int offset = 2;
        for (int i = 0; i < fieldCount; i++)
        {
            int len = BinaryPrimitives.ReadInt32BigEndian(span.Slice(offset, 4));
            offset += 4;
            if (len == -1)
            {
                _currentRow[i] = null;
            }
            else
            {
                var bytes = new byte[len];
                span.Slice(offset, len).CopyTo(bytes);
                _currentRow[i] = bytes;
                offset += len;
            }
        }
    }

    // ---------- Typed accessors ----------

    public string GetName(int ordinal) => _columns[ordinal].Name;
    public uint GetTypeOid(int ordinal) => _columns[ordinal].TypeOid;

    public bool IsDBNull(int ordinal)
    {
        EnsureRow();
        return _currentRow[ordinal] is null;
    }

    public ReadOnlySpan<byte> GetBytes(int ordinal)
    {
        EnsureValue(ordinal);
        return _currentRow[ordinal]!;
    }

    public string GetString(int ordinal)
    {
        EnsureValue(ordinal);
        return Encoding.UTF8.GetString(_currentRow[ordinal]!);
    }

    public short GetInt16(int ordinal)
        => short.Parse(GetTextSpan(ordinal), NumberStyles.Integer, CultureInfo.InvariantCulture);

    public int GetInt32(int ordinal)
        => int.Parse(GetTextSpan(ordinal), NumberStyles.Integer, CultureInfo.InvariantCulture);

    public long GetInt64(int ordinal)
        => long.Parse(GetTextSpan(ordinal), NumberStyles.Integer, CultureInfo.InvariantCulture);

    public float GetFloat(int ordinal)
        => float.Parse(GetTextSpan(ordinal), NumberStyles.Float, CultureInfo.InvariantCulture);

    public double GetDouble(int ordinal)
        => double.Parse(GetTextSpan(ordinal), NumberStyles.Float, CultureInfo.InvariantCulture);

    public decimal GetDecimal(int ordinal)
        => decimal.Parse(GetTextSpan(ordinal), NumberStyles.Number, CultureInfo.InvariantCulture);

    public bool GetBoolean(int ordinal)
    {
        var s = GetTextSpan(ordinal);
        if (s.Length == 1) return s[0] == 't' || s[0] == 'T' || s[0] == '1';
        return bool.Parse(s);
    }

    public Guid GetGuid(int ordinal)
        => Guid.Parse(GetTextSpan(ordinal));

    public DateTime GetDateTime(int ordinal)
        => DateTime.Parse(GetTextSpan(ordinal), CultureInfo.InvariantCulture,
                          DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    /// Returns the value as its natural CLR type based on the column's Postgres type OID.
    public object? GetValue(int ordinal)
    {
        if (IsDBNull(ordinal)) return DBNull.Value;
        return _columns[ordinal].TypeOid switch
        {
            PgOid.Bool => GetBoolean(ordinal),
            PgOid.Int2 => GetInt16(ordinal),
            PgOid.Int4 => GetInt32(ordinal),
            PgOid.Int8 => GetInt64(ordinal),
            PgOid.Float4 => GetFloat(ordinal),
            PgOid.Float8 => GetDouble(ordinal),
            PgOid.Numeric => GetDecimal(ordinal),
            PgOid.Uuid => GetGuid(ordinal),
            PgOid.Timestamp or PgOid.TimestampTz or PgOid.Date => GetDateTime(ordinal),
            _ => GetString(ordinal),
        };
    }

    private ReadOnlySpan<char> GetTextSpan(int ordinal)
    {
        EnsureValue(ordinal);
        // For hot paths we could avoid string alloc via Utf8Parser; keeping this simple.
        return Encoding.UTF8.GetString(_currentRow[ordinal]!).AsSpan();
    }

    private void EnsureValue(int ordinal)
    {
        EnsureRow();
        if (_currentRow[ordinal] is null)
            throw new InvalidCastException($"Column {ordinal} ({GetName(ordinal)}) is NULL.");
    }

    private void EnsureRow()
    {
        if (!_hasRow)
            throw new InvalidOperationException("No current row. Call ReadAsync first.");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(PgDataReader));
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        if (!_resultSetExhausted)
        {
            try { await DrainToReadyForQueryAsync(CancellationToken.None).ConfigureAwait(false); }
            catch { /* connection may be broken; caller handles */ }
        }
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
}
