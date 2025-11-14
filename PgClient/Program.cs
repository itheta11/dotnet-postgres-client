using System.Text;
using BenchmarkDotNet.Running;
using PgClient;
using PgClient.Benchmark;

var summary = BenchmarkRunner.Run<Benchmark>();

// /**


// */
// //postgresql://postgres.sjdxtmfvjsodboienfdy:[YOUR-PASSWORD]@aws-1-ap-south-1.pooler.supabase.com:5432/postgres
// ConnectionParameters connectionParameters = new ConnectionParameters()
// {
//     Hostname = "aws-1-ap-south-1.pooler.supabase.com",
//     Port = 5432,
//     Username = "postgres.sjdxtmfvjsodboienfdy",
//     Password = "Anupadmin123@#",
//     Database = "postgres",
//     ApplicationName = "pgclient",
//     FallbackApplicationName = "pgclient",
// };
// //Anupadmin123@#
// /***
// {
//     Hostname = "postgresql://postgres.sjdxtmfvjsodboienfdy",
//     Port = 5432,
//     Username = "admin",
//     Password = "admin123",
//     Database = "testdb",
//     ApplicationName = "pgclient",
//     FallbackApplicationName = "pgclient",
// };
// */
// using PgConnection pgConnection = new PgConnection(connectionParameters);
// await pgConnection.ConnectAsync();
// var res = pgConnection.ExecuteQuery("Select * from \"Movie\"");
// pgConnection.Close();


// Console.WriteLine("Completed");

