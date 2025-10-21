using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using PgClient;
using PgClient.Utilities;
using PgClient.MessageController;
using PgClient.Protocol;
using PgClient.Response;
using PgClient.QueryController;

public class PgConnection : IAsyncDisposable, IDisposable
{

    private bool _disposed;
    private TcpClient? _tcpClient;
    private NetworkStream? _networkStream;
    private ConnectionParameters _connectionParams;
    private readonly SemaphoreSlim _stateLock = new(1, 1);

    public PgConnectionState _connectionState { get; private set; } = PgConnectionState.Disconnected;

    private int _Pid;
    private int _SecretKey;
    public PgConnection(ConnectionParameters connectionParams)
    {
        _connectionParams = connectionParams;
    }

    public async Task ConnectAsync()
    {
        ThrowIfDisposed();
        await _stateLock.WaitAsync().ConfigureAwait(false);

        try
        {
            if (_connectionState == PgConnectionState.Ready)
                return;

            _connectionState = PgConnectionState.Connecting;
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_connectionParams.Hostname, _connectionParams.Port);

            _networkStream = _tcpClient.GetStream();

            Dictionary<string, string> connectionDict = new Dictionary<string, string>()
            {
                {"user", _connectionParams.Username },
                {"database", _connectionParams.Database},
            };
            SendStartupMessage(connectionDict);
            MessageController messageController = new MessageController(_connectionParams);
            (_connectionState, _Pid, _SecretKey) = messageController.HandleBackendMessages(_networkStream);
        }
        catch (Exception ex)
        {
            _connectionState = PgConnectionState.Faulted;
            throw;
        }
        finally
        {
            _stateLock.Release();
        }
    }

    public PgResult? ExecuteQuery(string query)
    {
        ThrowIfDisposed();
        _stateLock.Wait();
        PgResult? result = null;
        try
        {
            QueryController controller = new QueryController();
            result = controller.HandleBackendQueryMessages(_networkStream, query);
            return result;
        }
        catch (Exception ex)
        {
            _connectionState = PgConnectionState.Faulted;
            throw;
        }
        finally
        {
            _stateLock.Release();
        }

    }

    public void Close()
    {
        _tcpClient?.Close();
        _networkStream?.Dispose();
        _stateLock.Dispose();
        _connectionState = PgConnectionState.Closed;

    }


    public void SendStartupMessage(Dictionary<string, string> options)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms, Encoding.UTF8);

        writer.Write(new byte[4]); //placeholder length
        writer.Write(Helper.ToBigEndian(196608)); /// protocol 3.0 (0x00030000)
        foreach (var option in options)
        {
            Helper.WriteCString(writer, option.Key);
            Helper.WriteCString(writer, option.Value);
        }
        Helper.WriteCString(writer, "client_encoding");
        Helper.WriteCString(writer, "UTF8");
        writer.Write((byte)0);  /// terminator 

        int len = (int)ms.Length;
        ms.Position = 0;
        writer.Write(Helper.ToBigEndian(len));

        byte[] bytes = ms.ToArray();
        var check = Encoding.UTF8.GetString(bytes);
        _networkStream?.Write(bytes, 0, bytes.Length);
    }

    #region Disposing resources
    ~PgConnection()
    {
        DisposeAsyncCore(finalizing: true).AsTask().GetAwaiter().GetResult();
    }
    public void Dispose()
    {
        DisposeAsyncCore(finalizing: false).AsTask().GetAwaiter().GetResult();
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore(finalizing: false).ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
    private async ValueTask DisposeAsyncCore(bool finalizing)
    {
        if (_disposed) return;

        _disposed = true;

        // disposing in async way
        try
        {
            if (_networkStream != null)
            {
                await _networkStream.DisposeAsync().ConfigureAwait(false);
            }
            _tcpClient?.Dispose();
            _connectionState = PgConnectionState.Closed;
        }
        catch (Exception ex)
        {
            if (finalizing)
            {
                // Never throw from a finalizer — just log quietly
                try
                {
                    System.Diagnostics.Debug.WriteLine($"[Finalizer] PgConnection cleanup failed: {ex.Message}");
                }
                catch { /* swallow */ }
            }
            else
            {
                // Safe to log normally
                Console.WriteLine($"Error disposing PgConnection: {ex.Message}");
            }
        }
        finally
        {
            _stateLock.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(PgConnection));
        }
    }


    #endregion


}