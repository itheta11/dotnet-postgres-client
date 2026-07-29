using System.Buffers;
using System.Buffers.Binary;
using PgClient.BufferUtils;
using PgClient.Protocol;
using PgClient.Response;
using PgClient.Utilities;

namespace PgClient.Query;

/// A write-only stream that pipes bytes into a Postgres COPY FROM STDIN command.
///
/// Callers write the raw COPY payload (usually a CSV or TSV text block, or the
/// PGCOPY binary header + rows). Disposing the stream sends CopyDone, drains the
/// server's CommandComplete + ReadyForQuery, and returns the connection to
/// idle. To abort, call <see cref="Cancel"/> or <see cref="CancelAsync"/> before
/// disposing.
public sealed class PgCopyInStream : Stream
{
    private readonly Stream _stream;
    private readonly BufferStreamReader _protocol;
    private readonly Action<PostgresProtocol.TransactionStatus>? _onReadyForQuery;
    private bool _disposed;

    public CommandTag CommandTag { get; private set; } = CommandTag.Empty;

    internal PgCopyInStream(
        Stream stream, BufferStreamReader protocol,
        Action<PostgresProtocol.TransactionStatus>? onReadyForQuery)
    {
        _stream = stream;
        _protocol = protocol;
        _onReadyForQuery = onReadyForQuery;
    }

    public override bool CanRead => false;
    public override bool CanWrite => !_disposed;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteFrame(new ReadOnlySpan<byte>(buffer, offset, count));
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int total = 1 + 4 + buffer.Length;
        byte[] frame = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            frame[0] = (byte)PostgresProtocol.FrontendMessageCode.CopyData;
            BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1, 4), 4 + buffer.Length);
            buffer.CopyTo(frame.AsMemory(5, buffer.Length));
            await _stream.WriteAsync(frame.AsMemory(0, total), cancellationToken).ConfigureAwait(false);
        }
        finally { ArrayPool<byte>.Shared.Return(frame); }
    }

    private void WriteFrame(ReadOnlySpan<byte> data)
    {
        int total = 1 + 4 + data.Length;
        byte[] frame = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            frame[0] = (byte)PostgresProtocol.FrontendMessageCode.CopyData;
            BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1, 4), 4 + data.Length);
            data.CopyTo(frame.AsSpan(5));
            _stream.Write(frame, 0, total);
        }
        finally { ArrayPool<byte>.Shared.Return(frame); }
    }

    /// Aborts the COPY on the server. Must be called before Dispose.
    public void Cancel(string message = "COPY cancelled by client")
    {
        byte[] msg = System.Text.Encoding.UTF8.GetBytes(message);
        int total = 1 + 4 + msg.Length + 1;
        byte[] frame = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            frame[0] = (byte)PostgresProtocol.FrontendMessageCode.CopyFail;
            BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1, 4), 4 + msg.Length + 1);
            msg.CopyTo(frame.AsSpan(5));
            frame[5 + msg.Length] = 0;
            _stream.Write(frame, 0, total);
        }
        finally { ArrayPool<byte>.Shared.Return(frame); }
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            // CopyDone: 'c' + Int32 length (=4)
            Span<byte> done = stackalloc byte[5];
            done[0] = (byte)PostgresProtocol.FrontendMessageCode.CopyDone;
            BinaryPrimitives.WriteInt32BigEndian(done.Slice(1), 4);
            _stream.Write(done);

            DrainToReadyForQuery();
        }
        catch { /* swallow during dispose */ }

        base.Dispose(disposing);
    }

    private void DrainToReadyForQuery()
    {
        while (true)
        {
            var (code, _, payload) = _protocol.ReadMessage(_stream);
            switch ((PostgresProtocol.BackendMessageCode)code)
            {
                case PostgresProtocol.BackendMessageCode.CommandComplete:
                    CommandTag = CommandTag.Parse(payload);
                    break;
                case PostgresProtocol.BackendMessageCode.ErrorResponse:
                    var info = PgErrorInfo.Parse(payload);
                    DrainRemaining();
                    throw new PgException(info);
                case PostgresProtocol.BackendMessageCode.ReadyForQuery:
                    if (payload.Length > 0)
                        _onReadyForQuery?.Invoke((PostgresProtocol.TransactionStatus)payload[0]);
                    return;
            }
        }
    }

    private void DrainRemaining()
    {
        while (true)
        {
            var (code, _, _) = _protocol.ReadMessage(_stream);
            if ((PostgresProtocol.BackendMessageCode)code == PostgresProtocol.BackendMessageCode.ReadyForQuery)
                return;
        }
    }
}

/// A read-only stream that surfaces server-supplied COPY TO STDOUT bytes.
///
/// Each server CopyData message becomes a chunk; the stream ends when the server
/// sends CopyDone. The stream then drains to ReadyForQuery on dispose.
public sealed class PgCopyOutStream : Stream
{
    private readonly Stream _stream;
    private readonly BufferStreamReader _protocol;
    private readonly Action<PostgresProtocol.TransactionStatus>? _onReadyForQuery;
    private byte[]? _currentChunk;
    private int _chunkOffset;
    private bool _finished;
    private bool _disposed;

    public CommandTag CommandTag { get; private set; } = CommandTag.Empty;

    internal PgCopyOutStream(
        Stream stream, BufferStreamReader protocol,
        Action<PostgresProtocol.TransactionStatus>? onReadyForQuery)
    {
        _stream = stream;
        _protocol = protocol;
        _onReadyForQuery = onReadyForQuery;
    }

    public override bool CanRead => !_disposed;
    public override bool CanWrite => false;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_finished) return 0;

        if (_currentChunk is null || _chunkOffset >= _currentChunk.Length)
        {
            if (!NextChunk()) return 0;
        }

        int available = _currentChunk!.Length - _chunkOffset;
        int take = Math.Min(available, count);
        Buffer.BlockCopy(_currentChunk, _chunkOffset, buffer, offset, take);
        _chunkOffset += take;
        return take;
    }

    private bool NextChunk()
    {
        while (true)
        {
            var (code, _, payload) = _protocol.ReadMessage(_stream);
            switch ((PostgresProtocol.BackendMessageCode)code)
            {
                case PostgresProtocol.BackendMessageCode.CopyData:
                    _currentChunk = payload;
                    _chunkOffset = 0;
                    return true;
                case PostgresProtocol.BackendMessageCode.CopyDone:
                    _finished = true;
                    return false;
                case PostgresProtocol.BackendMessageCode.CommandComplete:
                    CommandTag = CommandTag.Parse(payload);
                    break;
                case PostgresProtocol.BackendMessageCode.ErrorResponse:
                    _finished = true;
                    throw new PgException(PgErrorInfo.Parse(payload));
                case PostgresProtocol.BackendMessageCode.ReadyForQuery:
                    _finished = true;
                    if (payload.Length > 0)
                        _onReadyForQuery?.Invoke((PostgresProtocol.TransactionStatus)payload[0]);
                    return false;
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            // Drain any remaining chunks + CommandComplete + ReadyForQuery.
            while (NextChunk()) { }
        }
        catch { /* swallow */ }
        base.Dispose(disposing);
    }
}
