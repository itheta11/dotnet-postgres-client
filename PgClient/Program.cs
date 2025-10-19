using System.Text;
using PgClient;

/**


*/


var serializer = new Serializer();
Dictionary<string, string> options = new Dictionary<string, string>()
{
    {"user", "postgres"}
};
var res = serializer.StartUpBytes(options);
Console.WriteLine(Encoding.UTF8.GetString(res));