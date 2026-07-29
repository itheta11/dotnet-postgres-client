using PgClient.MessageHandlers;
using PgClient.BufferUtils;
using PgClient.Protocol;
using PgClient.Response;

namespace PgClient.MessageController;

public sealed class PgMessageController
{
    private readonly AuthenticationHandler _authenticationHandler;
    private int _pid;
    private int _secretKey;

    public PgMessageController(ConnectionParameters connectionParameters)
    {
        _authenticationHandler = new AuthenticationHandler(connectionParameters);
    }

    /// Runs the startup + authentication loop synchronously, using a caller-owned
    /// reader that is reused for the entire connection lifetime.
    public (PgConnectionState State, int Pid, int SecretKeyId, PostgresProtocol.TransactionStatus TxStatus)
        HandleBackendMessages(Stream stream, BufferStreamReader reader)
    {
        while (true)
        {
            var (code, _, payload) = reader.ReadMessage(stream);
            var msgCode = (PostgresProtocol.BackendMessageCode)code;

            switch (msgCode)
            {
                case PostgresProtocol.BackendMessageCode.Authentication:
                    _authenticationHandler.Handler(payload, stream);
                    break;

                case PostgresProtocol.BackendMessageCode.ParameterStatus:
                    break;

                case PostgresProtocol.BackendMessageCode.BackendKeyData:
                    var backendKeyHandler = new BackendKeyHandler();
                    (_pid, _secretKey) = backendKeyHandler.HandleBankendKey(payload);
                    break;

                case PostgresProtocol.BackendMessageCode.NoticeResponse:
                    break;

                case PostgresProtocol.BackendMessageCode.ErrorResponse:
                    throw new PgException(PgErrorInfo.Parse(payload));

                case PostgresProtocol.BackendMessageCode.ReadyForQuery:
                    var tx = payload.Length >= 1
                        ? (PostgresProtocol.TransactionStatus)payload[0]
                        : PostgresProtocol.TransactionStatus.Idle;
                    return (PgConnectionState.Ready, _pid, _secretKey, tx);

                default:
                    break;
            }
        }
    }
}
