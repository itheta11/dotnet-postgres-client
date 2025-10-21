using System.Text;
using PgClient;

/**


*/

ConnectionParameters connectionParameters = new ConnectionParameters()
{
    Hostname = "host.docker.internal",
    Port = 5432,
    Username = "admin",
    Password = "admin123",
    Database = "testdb",
    ApplicationName = "pgclient",
    FallbackApplicationName = "pgclient",
};

using PgConnection pgConnection = new PgConnection(connectionParameters);
await pgConnection.ConnectAsync();
var res = pgConnection.ExecuteQuery("Select * from movie");
pgConnection.Close();


Console.WriteLine("Completed");