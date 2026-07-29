using System.Net.Sockets;
using System.Text;
using PgClient;
using PgClient.BufferUtils;
using PgClient.MessageController;
using PgClient.Pool;
using PgClient.Protocol;
using PgClient.Query;
using PgClient.QueryController;
using PgClient.Response;
using PgClient.Ssl;
using PgClient.Types;
using PgClient.Utilities;

/// A single Postgres backend connection.
///
/// Thread-safety: instance methods are serialised by a semaphore. Concurrent
/// command execution on the same connection is not supported — callers must
/// not overlap operations.
public sealed class PgConnection : IAsyncDisposable, IDisposable
{
    private bool _disposed;
    private TcpClient? _tcpClient;
    private Stream? _stream;
    private BufferStreamReader? _protocolReader;

    private readonly ConnectionParameters _connectionParams;
    private readonly SemaphoreSlim _stateLock = new(1, 1);
    private readonly PreparedStatementCache _prepared;

    public PgConnectionState State { get; private set; } = PgConnectionState.Disconnected;
    public PostgresProtocol.TransactionStatus TransactionStatus { get; private set; }
        = PostgresProtocol.TransactionStatus.Idle;

    public int ProcessId { get; private set; }
    public int SecretKey { get; private set; }

    /// True when TLS was negotiated with the server.
    public bool IsSecure { get; private set; }

    /// UTC timestamp of when the underlying socket was opened.
    public DateTime OpenedAtUtc { get; private set; }

    /// The pool owning this connection, if any. Set by <see cref="PgConnectionPool"/>.
    internal PgConnectionPool? Pool { get; set; }

    /// True when the connection has entered a non-recoverable state and must
    /// not be reused by the pool.
    public bool IsBroken => State == PgConnectionState.Faulted;

    /// The type registry used for extended-query parameter encoding and reader
    /// value decoding. Defaults to the shared <see cref="PgTypeRegistry.Default"/>.
    public PgTypeRegistry TypeRegistry { get; set; } = PgTypeRegistry.Default;

    /// Raised for each server-sent NoticeResponse during a command.
    public event Action<PgErrorInfo>? Notice;

    public PgConnection(ConnectionParameters connectionParams)
    {
        _connectionParams = connectionParams;
        _prepared = new PreparedStatementCache(
            connectionParams.MaxAutoPrepare,
            connectionParams.AutoPrepareMinUsages);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (State == PgConnectionState.Ready) return;

            State = PgConnectionState.Connecting;
            _tcpClient = new TcpClient { NoDelay = true };

            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                if (_connectionParams.ConnectTimeout > TimeSpan.Zero)
                    linked.CancelAfter(_connectionParams.ConnectTimeout);

                await _tcpClient.ConnectAsync(
                    _connectionParams.Hostname, _connectionParams.Port, linked.Token)
                    .ConfigureAwait(false);
            }

            NetworkStream raw = _tcpClient.GetStream();

            var (final, secure) = await SslNegotiator.NegotiateAsync(
                raw,
                _connectionParams.Hostname,
                _connectionParams.SslMode,
                _connectionParams.TrustServerCertificate,
                _connectionParams.ServerCertificateValidationCallback,
                cancellationToken).ConfigureAwait(false);

            _stream = final;
            IsSecure = secure;
            _protocolReader = new BufferStreamReader();
            OpenedAtUtc = DateTime.UtcNow;

            SendStartupMessage(BuildStartupOptions());

            var controller = new PgMessageController(_connectionParams);
            var (state, pid, secret, tx) = controller.HandleBackendMessages(_stream, _protocolReader);
            State = state;
            ProcessId = pid;
            SecretKey = secret;
            TransactionStatus = tx;
        }
        catch
        {
            State = PgConnectionState.Faulted;
            throw;
        }
        finally
        {
            _stateLock.Release();
        }
    }

    // ── Simple query protocol ──────────────────────────────────────────────

    public async Task<PgDataReader> ExecuteReaderAsync(string query, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureReady();

        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var controller = new PgQueryController();
            var reader = controller.ExecuteReader(
                _stream!,
                _protocolReader!,
                query,
                onReadyForQuery: tx => TransactionStatus = tx,
                onNotice: n => Notice?.Invoke(n));
            return reader;
        }
        catch
        {
            State = PgConnectionState.Faulted;
            throw;
        }
        finally
        {
            _stateLock.Release();
        }
    }

    public async Task<CommandTag> ExecuteNonQueryAsync(string sql, CancellationToken cancellationToken = default)
    {
        await using var reader = await ExecuteReaderAsync(sql, cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { }
        return reader.CommandTag;
    }

    public async Task<object?> ExecuteScalarAsync(string sql, CancellationToken cancellationToken = default)
    {
        await using var reader = await ExecuteReaderAsync(sql, cancellationToken).ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.FieldCount > 0)
        {
            return reader.GetValue(0);
        }
        return null;
    }

    // ── Extended query protocol (parameters) ───────────────────────────────

    /// Executes a parameterized statement using the extended query protocol
    /// (Parse/Bind/Describe/Execute/Sync). Auto-preparation kicks in when the
    /// same SQL has been executed at least
    /// <see cref="ConnectionParameters.AutoPrepareMinUsages"/> times and the
    /// cache is not full.
    public async Task<PgDataReader> ExecuteReaderAsync(
        string sql,
        IReadOnlyList<PgParameter> parameters,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureReady();
        ArgumentNullException.ThrowIfNull(parameters);

        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string? cachedName = _prepared.TryGetOrPromote(sql, out string? evicted);

            if (evicted is not null)
            {
                ExtendedQueryProtocol.WriteCloseStatement(_stream!, evicted);
                ExtendedQueryProtocol.WriteSync(_stream!);
                DrainToReadyForQuery();
            }

            string stmtName = cachedName ?? string.Empty;

            ExtendedQueryProtocol.SendParseBindExecute(
                _stream!, stmtName, portalName: string.Empty, sql, parameters, TypeRegistry);

            var reader = new PgDataReader(
                _stream!, _protocolReader!,
                onReadyForQuery: tx => TransactionStatus = tx,
                onNotice: n => Notice?.Invoke(n));
            return reader;
        }
        catch
        {
            State = PgConnectionState.Faulted;
            throw;
        }
        finally
        {
            _stateLock.Release();
        }
    }

    public async Task<CommandTag> ExecuteNonQueryAsync(
        string sql, IReadOnlyList<PgParameter> parameters, CancellationToken cancellationToken = default)
    {
        await using var reader = await ExecuteReaderAsync(sql, parameters, cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { }
        return reader.CommandTag;
    }

    public async Task<object?> ExecuteScalarAsync(
        string sql, IReadOnlyList<PgParameter> parameters, CancellationToken cancellationToken = default)
    {
        await using var reader = await ExecuteReaderAsync(sql, parameters, cancellationToken).ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.FieldCount > 0)
            return reader.GetValue(0);
        return null;
    }

    // ── Pool integration ───────────────────────────────────────────────────

    internal void MarkRented() { /* placeholder for future counters */ }

    /// Resets session state and readies the connection for the next borrower.
    internal void MarkIdle()
    {
        try
        {
            PgQueryController.SendQuery(_stream!, "DISCARD ALL");
            DrainToReadyForQuery();

            // DISCARD ALL wipes server-side prepared statements — clear the local cache too.
            foreach (var _ in _prepared.Drain()) { }
        }
        catch
        {
            State = PgConnectionState.Faulted;
        }
    }

    /// Force-closes the connection without returning it to a pool.
    internal void CloseInternal()
    {
        var prevPool = Pool;
        Pool = null;
        try { Close(); }
        finally { Pool = prevPool; }
    }

    // ── Teardown ───────────────────────────────────────────────────────────

    public void Close()
    {
        if (_disposed) return;
        try
        {
            if (_stream is not null && _tcpClient?.Connected == true && !IsBroken)
            {
                try { PgQueryController.SendTerminate(_stream); }
                catch { /* server may already be gone */ }
            }
        }
        finally
        {
            _protocolReader?.Dispose();
            _stream?.Dispose();
            _tcpClient?.Close();
            State = PgConnectionState.Closed;
        }
    }

    private void DrainToReadyForQuery()
    {
        while (true)
        {
            var msg = _protocolReader!.ReadMessage(_stream!);
            if (msg.Code == (byte)PostgresProtocol.BackendMessageCode.ReadyForQuery)
            {
                if (msg.Payload.Length > 0)
                    TransactionStatus = (PostgresProtocol.TransactionStatus)msg.Payload[0];
                return;
            }
            if (msg.Code == (byte)PostgresProtocol.BackendMessageCode.ErrorResponse)
            {
                throw PgException.FromErrorResponse(msg.Payload);
            }
        }
    }

    private Dictionary<string, string> BuildStartupOptions()
    {
        var options = new Dictionary<string, string>
        {
            ["user"] = _connectionParams.Username,
            ["database"] = _connectionParams.Database,
        };
        if (!string.IsNullOrEmpty(_connectionParams.ApplicationName))
            options["application_name"] = _connectionParams.ApplicationName;
        return options;
    }

    private void SendStartupMessage(Dictionary<string, string> options)
    {
        using var ms = new MemoryStream(128);
        using var writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        writer.Write(new byte[4]);                     // length placeholder
        writer.Write(Helper.ToBigEndian(196608));      // protocol version 3.0
        foreach (var option in options)
        {
            Helper.WriteCString(writer, option.Key);
            Helper.WriteCString(writer, option.Value);
        }
        Helper.WriteCString(writer, "client_encoding");
        Helper.WriteCString(writer, "UTF8");
        Helper.WriteCString(writer, "DateStyle");
        Helper.WriteCString(writer, "ISO, YMD");
        Helper.WriteCString(writer, "extra_float_digits");
        Helper.WriteCString(writer, "3");
        writer.Write((byte)0);                         // terminator

        int len = (int)ms.Length;
        ms.Position = 0;
        writer.Write(Helper.ToBigEndian(len));

        byte[] bytes = ms.GetBuffer();
        _stream!.Write(bytes, 0, (int)ms.Length);
    }

    private void EnsureReady()
    {
        if (State != PgConnectionState.Ready)
            throw new InvalidOperationException($"Connection is not ready (state: {State}).");
        if (_stream is null || _protocolReader is null)
            throw new InvalidOperationException("Connection is not initialized.");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(PgConnection));
    }

    public void Dispose()
    {
        if (_disposed) return;

        // If this connection is owned by a pool, return it instead of closing.
        var pool = Pool;
        if (pool is not null && !IsBroken)
        {
            pool.Return(this);
            return;
        }

        _disposed = true;
        try { Close(); } catch { /* swallow during dispose */ }
        _stateLock.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}
