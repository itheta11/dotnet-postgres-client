namespace PgClient;


public class PgSqlClient
{

    private readonly ConnectionParameters _connectionParams;
    public PgSqlClient(ConnectionParameters connectionParams)
    {
        _connectionParams = connectionParams;
    }
}