using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using PgClient.Authentication;
using PgClient.BufferUtils;
using PgClient.Protocol;

namespace PgClient.MessageController;

public class MessageController
{
    private AuthenticationHandler authenticationHandler;
    public MessageController(ConnectionParameters connectionParameters)
    {
        authenticationHandler = new AuthenticationHandler(connectionParameters);
    }
    
    public void HandleMessages(NetworkStream stream)
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
                    break;

                case PostgresProtocol.BackendMessageCode.BackendKeyData:
                    break;
                case PostgresProtocol.BackendMessageCode.ReadyForQuery:
                    return;
                case PostgresProtocol.BackendMessageCode.ErrorResponse:
                    Console.WriteLine($"server error {Encoding.UTF8.GetString(payload)}");
                    throw new Exception($"server error {Encoding.UTF8.GetString(payload)}");
                default:
                    break;
            }

        }
    }
}