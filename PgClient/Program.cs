using System.Text;
using BenchmarkDotNet.Running;
using PgClient;
using PgClient.Benchmark;

//var summary = BenchmarkRunner.Run<Benchmark>();

ConnectionParameters connectionParameters = new ConnectionParameters()
{
    Hostname = "172.17.0.1",
    Port = 5432,
    Username = "admin",
    Password = "anup",
    Database = "movie",
    ApplicationName = "",
    FallbackApplicationName = "",
};

using PgConnection pgConnection = new PgConnection(connectionParameters);
await pgConnection.ConnectAsync();
string query = "SELECT * FROM Movies ORDER BY movieid LIMIT 10; ";
await foreach (var row in pgConnection.ExecuteReaderAsync(query))
{
    Console.WriteLine(string.Join(", ", row));
}
//var res = pgConnection.ExecuteQuery("Select * from Movies");
pgConnection.Close();


Console.WriteLine("Completed");

