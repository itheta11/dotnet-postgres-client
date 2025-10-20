using System.Text;
using PgClient;

/**


*/

ConnectionParameters connectionParameters = new ConnectionParameters()
{
    Hostname = "host.docker.internal",
    Port = 5432,
    Username = "anup",
    Password = "anup123",
    Database = "testdb",
    ApplicationName = "pgclient",
    FallbackApplicationName = "pgclient",
};

using PgConnection pgConnection = new PgConnection(connectionParameters);
await pgConnection.ConnectAsync();
pgConnection.ExecuteQuery("");
pgConnection.Close();


Console.WriteLine("Completed");