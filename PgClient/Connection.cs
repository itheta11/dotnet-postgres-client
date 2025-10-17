using System.Runtime.CompilerServices;
using PgClient;

public class Connection
{
    private string ssl { get; set; }

    private ConnectionStatus Status { get; set; }

    public void Connect(string hostname, int port)
    {
        Status = ConnectionStatus.CONNECTING;
    }
}