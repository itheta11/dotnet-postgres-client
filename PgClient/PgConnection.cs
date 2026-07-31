using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using PgClient;
using PgClient.BufferUtils;
using PgClient.Diagnostics;
using PgClient.MessageController;
using PgClient.Pool;
using PgClient.Protocol;
using PgClient.Query;
using PgClient.QueryController;
using PgClient.Response;
using PgClient.Ssl;
using PgClient.Types;
using PgClient.Utilities;

namespace PgClient;

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
    private readonly ILogger _logger;
    private readonly Dictionary<string, string> _parameterStatus = new(StringComparer.OrdinalIgnoreCase);

    public PgConnectionState State { get; private set; } = PgConnectionState.Disconnected;
    public PostgresProtocol.TransactionStatus TransactionStatus { get; private set; }
        = PostgresProtocol.TransactionStatus.Idle;

    public int ProcessId { get; private set; }
    public int SecretKey { get; private set; }

    /// True when TLS was negotiated with the server.
    public bool IsSecure { get; private set; }

    /// UTC timestamp of when the underlying socket was opened.
    public DateTime OpenedAtUtc { get; private set; }

    /// <summary>Value of the server's <c>server_version</c> <c>ParameterStatus</c>, e.g. "16.3".</summary>
    public string ServerVersion => _parameterStatus.TryGetValue("server_version", out var v) ? v : string.Empty;

    /// <summary>Read-only view of the last known server parameter statuses.</summary>
    public IReadOnlyDictionary<string, string> ParameterStatus => _parameterStatus;

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

    /// Raised for each LISTEN/NOTIFY notification received on this connection.
    public event EventHandler<PgNotificationEventArgs>? Notification;

    public PgConnection(ConnectionParameters connectionParams)
    {
        _connectionParams = connectionParams;
        _prepared = new PreparedStatementCache(
            connectionParams.MaxAutoPrepare,
            connectionParams.AutoPrepareMinUsages);
        _logger = connectionParams.GetLogger("PgClient.PgConnection");
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
            ConfigureKeepAlive(_tcpClient);

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
            var (state, pid, secret, tx) = controller.HandleBackendMessages(
                _stream, _protocolReader,
                onParameterStatus: (name, value) => _parameterStatus[name] = value);
            State = state;
            ProcessId = pid;
            SecretKey = secret;
            TransactionStatus = tx;
            PgClientMetrics.ConnectionsOpened.Add(1);
            _logger.LogInformation("PgClient connected to {Host}:{Port} as {User}/{Db} (server_version={ServerVersion}, tls={IsSecure})",
                _connectionParams.Hostname, _connectionParams.Port, _connectionParams.Username, _connectionParams.Database, ServerVersion, IsSecure);
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

        using var linked = CreateCommandCts(cancellationToken);
        await _stateLock.WaitAsync(linked.Token).ConfigureAwait(false);
        var start = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            var controller = new PgQueryController();
            var reader = controller.ExecuteReader(
                _stream!,
                _protocolReader!,
                query,
                onReadyForQuery: tx => TransactionStatus = tx,
                onNotice: n => Notice?.Invoke(n),
                onNotification: RaiseNotification);
            PgClientMetrics.CommandsExecuted.Add(1);
            return reader;
        }
        catch
        {
            PgClientMetrics.CommandsFailed.Add(1);
            State = PgConnectionState.Faulted;
            throw;
        }
        finally
        {
            PgClientMetrics.CommandDurationMs.Record(GetElapsedMs(start));
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

        using var linked = CreateCommandCts(cancellationToken);
        await _stateLock.WaitAsync(linked.Token).ConfigureAwait(false);
        var start = System.Diagnostics.Stopwatch.GetTimestamp();
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
                onNotice: n => Notice?.Invoke(n),
                onNotification: RaiseNotification);
            PgClientMetrics.CommandsExecuted.Add(1);
            return reader;
        }
        catch
        {
            PgClientMetrics.CommandsFailed.Add(1);
            State = PgConnectionState.Faulted;
            throw;
        }
        finally
        {
            PgClientMetrics.CommandDurationMs.Record(GetElapsedMs(start));
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

    // ── Transactions ───────────────────────────────────────────────────────

    /// Opens a transaction with the given isolation level.
    public async Task<PgTransaction> BeginTransactionAsync(
        System.Data.IsolationLevel isolationLevel = System.Data.IsolationLevel.ReadCommitted,
        CancellationToken cancellationToken = default)
    {
        string sql = isolationLevel switch
        {
            System.Data.IsolationLevel.ReadUncommitted => "BEGIN ISOLATION LEVEL READ UNCOMMITTED",
            System.Data.IsolationLevel.ReadCommitted => "BEGIN ISOLATION LEVEL READ COMMITTED",
            System.Data.IsolationLevel.RepeatableRead => "BEGIN ISOLATION LEVEL REPEATABLE READ",
            System.Data.IsolationLevel.Serializable => "BEGIN ISOLATION LEVEL SERIALIZABLE",
            System.Data.IsolationLevel.Snapshot => "BEGIN ISOLATION LEVEL REPEATABLE READ",
            System.Data.IsolationLevel.Unspecified => "BEGIN",
            _ => "BEGIN",
        };
        await ExecuteNonQueryAsync(sql, cancellationToken).ConfigureAwait(false);
        return new PgTransaction(this, isolationLevel);
    }

    // ── LISTEN/NOTIFY ──────────────────────────────────────────────────────

    /// Blocks until the next NotificationResponse arrives (or the token cancels).
    /// LISTEN itself must be issued with <see cref="ExecuteNonQueryAsync(string, CancellationToken)"/>.
    public async Task WaitAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        EnsureReady();
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler(object? _, PgNotificationEventArgs __) => tcs.TrySetResult();
        Notification += Handler;
        try
        {
            using (cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken)))
                await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            Notification -= Handler;
        }
    }

    private void RaiseNotification(int pid, string channel, string payload)
        => Notification?.Invoke(this, new PgNotificationEventArgs(pid, channel, payload));

    // ── Cancel ─────────────────────────────────────────────────────────────

    /// Sends a CancelRequest on a fresh TCP connection using this session's
    /// backend PID and secret key. This is the only way to interrupt a long-
    /// running query server-side. Safe to call from any thread.
    public Task CancelAsync(CancellationToken cancellationToken = default)
    {
        if (ProcessId == 0 || SecretKey == 0)
            throw new InvalidOperationException("Backend key data has not been received; cannot cancel.");

        return PgCancelRequest.SendAsync(
            _connectionParams.Hostname, _connectionParams.Port,
            ProcessId, SecretKey, cancellationToken);
    }

    // ── COPY ───────────────────────────────────────────────────────────────

    /// Begins a COPY FROM STDIN and returns a write-only stream. The caller
    /// writes COPY payload bytes (CSV/TSV text or PGCOPY binary) and disposes
    /// the stream to end the copy. The stream MUST be disposed before issuing
    /// any other command.
    public async Task<PgClient.Query.PgCopyInStream> BeginCopyInAsync(string sql, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureReady();
        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PgQueryController.SendQuery(_stream!, sql);
            ExpectCopyResponse((byte)PostgresProtocol.BackendMessageCode.CopyInResponse);
            return new PgClient.Query.PgCopyInStream(_stream!, _protocolReader!, tx => TransactionStatus = tx);
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

    /// Begins a COPY TO STDOUT and returns a read-only stream over the server's bytes.
    public async Task<PgClient.Query.PgCopyOutStream> BeginCopyOutAsync(string sql, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureReady();
        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PgQueryController.SendQuery(_stream!, sql);
            ExpectCopyResponse((byte)PostgresProtocol.BackendMessageCode.CopyOutResponse);
            return new PgClient.Query.PgCopyOutStream(_stream!, _protocolReader!, tx => TransactionStatus = tx);
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

    private void ExpectCopyResponse(byte expected)
    {
        while (true)
        {
            var (code, _, payload) = _protocolReader!.ReadMessage(_stream!);
            if (code == expected) return;
            if (code == (byte)PostgresProtocol.BackendMessageCode.NoticeResponse)
            {
                Notice?.Invoke(PgErrorInfo.Parse(payload));
                continue;
            }
            if (code == (byte)PostgresProtocol.BackendMessageCode.ErrorResponse)
            {
                var info = PgErrorInfo.Parse(payload);
                DrainToReadyForQuery();
                throw new PgException(info);
            }
            if (code == (byte)PostgresProtocol.BackendMessageCode.ReadyForQuery)
                throw new InvalidOperationException("Server did not enter COPY mode for the given SQL.");
        }
    }

    // ── Pool integration ───────────────────────────────────────────────────

    /// Called by the pool immediately before handing the connection to a caller.
    internal void MarkRented() { /* placeholder */ }

    /// Resets session state and readies the connection for the next borrower.
    internal void MarkIdle()
    {
        if (_connectionParams.NoResetOnClose)
        {
            _prepared.Drain().ToList();
            return;
        }
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
            var wasClosed = State == PgConnectionState.Closed;
            State = PgConnectionState.Closed;
            if (!wasClosed) PgClientMetrics.ConnectionsClosed.Add(1);
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

    private CancellationTokenSource CreateCommandCts(CancellationToken cancellationToken)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_connectionParams.CommandTimeout > TimeSpan.Zero)
            cts.CancelAfter(_connectionParams.CommandTimeout);
        return cts;
    }

    private static double GetElapsedMs(long startTicks)
    {
        long delta = System.Diagnostics.Stopwatch.GetTimestamp() - startTicks;
        return delta * 1000.0 / System.Diagnostics.Stopwatch.Frequency;
    }

    private void ConfigureKeepAlive(TcpClient client)
    {
        if (!_connectionParams.TcpKeepAlive) return;
        var socket = client.Client;
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            int time = Math.Max(1, (int)_connectionParams.TcpKeepAliveTime.TotalSeconds);
            int interval = Math.Max(1, (int)_connectionParams.TcpKeepAliveInterval.TotalSeconds);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, time);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, interval);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 5);
        }
        catch (SocketException)
        {
            // Some platforms do not support fine-grained keepalive controls; silently continue.
        }
        catch (NotSupportedException)
        {
        }
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
