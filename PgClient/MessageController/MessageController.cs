using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using PgClient.MessageHandlers;
using PgClient.BufferUtils;
using PgClient.Protocol;
using System.Data;

namespace PgClient.MessageController;

public class MessageController
{
    private AuthenticationHandler authenticationHandler;

    private int _Pid;
    private int _SecretKey;
    public MessageController(ConnectionParameters connectionParameters)
    {
        authenticationHandler = new AuthenticationHandler(connectionParameters);
    }

    public (PgConnectionState state, int PId, int SecretKeyId) HandleBackendMessages(NetworkStream stream)
    {
        while (true)
        {
            using BufferStreamReader reader = new BufferStreamReader();
            var (code, length, payload) = reader.ReadMessage(stream);

            PostgresProtocol.BackendMessageCode msgCode = (PostgresProtocol.BackendMessageCode)code;
            switch (msgCode)
            {
                case PostgresProtocol.BackendMessageCode.Authentication:
                    authenticationHandler.Handler(payload, stream);
                    break;

                case PostgresProtocol.BackendMessageCode.ParameterStatus:
                    ////Console.WriteLine($"Parameter {Encoding.UTF8.GetString(payload)}");
                    break;

                case PostgresProtocol.BackendMessageCode.BackendKeyData:
                    ////Console.WriteLine($"Backend keyed data {Encoding.UTF8.GetString(payload)}");
                    BackendKeyHandler backendKeyHandler = new BackendKeyHandler();
                    (_Pid, _SecretKey) = backendKeyHandler.HandleBankendKey(payload);
                    break;
                case PostgresProtocol.BackendMessageCode.ReadyForQuery:
                    ////Console.WriteLine($"Ready for query {Encoding.UTF8.GetString(payload)}");
                    return (PgConnectionState.Ready, _Pid, _SecretKey);
                case PostgresProtocol.BackendMessageCode.ErrorResponse:
                    ////Console.WriteLine($"server error {Encoding.UTF8.GetString(payload)}");
                    throw new Exception($"server error {Encoding.UTF8.GetString(payload)}");
                default:
                    break;
            }

        }
    }
}