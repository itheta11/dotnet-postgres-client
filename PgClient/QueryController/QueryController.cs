using System;
using System.ComponentModel;
using System.Net.Sockets;
using System.Text;
using PgClient.BufferUtils;
using PgClient.Protocol;
using PgClient.Response;
using PgClient.Utilities;

namespace PgClient.QueryController;

public class QueryController
{
    public PgResult HandleBackendQueryMessages(NetworkStream stream, string query)
    {
        PgResult result = new PgResult();
        SendQuery(stream, query);
        while (true)
        {
            using BufferStreamReader reader = new BufferStreamReader();
            var (code, payload) = reader.ReadQueryMessage(stream);

            PostgresProtocol.BackendMessageCode msgCode = (PostgresProtocol.BackendMessageCode)code;

            switch (msgCode)
            {
                case PostgresProtocol.BackendMessageCode.RowDescription:
                    result.Columns = ParseRowDescription(payload);
                    break;
                case PostgresProtocol.BackendMessageCode.DataRow:
                    var row = ParseDataRowMessage(payload);
                    result.Rows.Add(row);
                    break;
                case PostgresProtocol.BackendMessageCode.CommandComplete:
                    break;
                case PostgresProtocol.BackendMessageCode.ErrorResponse:
                    //Console.WriteLine($"server error {Encoding.UTF8.GetString(payload)}");
                    throw new Exception($"server error {Encoding.UTF8.GetString(payload)}");
                case PostgresProtocol.BackendMessageCode.ReadyForQuery:
                    return result;
                default:
                    break;
            }

        }
    }

    public void SendQuery(NetworkStream stream, string query)
    {
        byte[] queryBytes = Encoding.UTF8.GetBytes(query);
        int length = 4 + queryBytes.Length + 1;  // length + query + null terminator

        using var ms = new MemoryStream();
        ms.WriteByte((byte)PostgresProtocol.FrontendMessageCode.Query);
        Helper.WriteInt32(ms, length);
        ms.Write(queryBytes, 0, queryBytes.Length);
        ms.WriteByte(0);

        stream.Write(ms.ToArray());
    }

    private List<PgRow?> ParseRowDescription(byte[] payload)
    {
        List<PgRow?> rows = new List<PgRow?>();
        var ms = new MemoryStream(payload);
        var reader = new BinaryReader(ms, Encoding.UTF8);

        short fieldCount = Helper.ReadInt16(reader);
        for (int i = 0; i < fieldCount; i++)
        {
            string name = Helper.ReadCString(reader);
            int tableOid = Helper.ReadInt32(reader);
            short columnAttr = Helper.ReadInt16(reader);
            int typeOid = Helper.ReadInt32(reader);
            short typeSize = Helper.ReadInt16(reader);
            int typeMod = Helper.ReadInt32(reader);
            string format = Helper.ReadInt16(reader) == 0 ? "text" : "binary";

            rows.Add(new PgRow()
            {
                Name = name,
                TableOid = tableOid,
                ColumnAttribute = columnAttr,
                TypeOid = typeOid,
                TypeSize = typeSize,
                TypeModifier = typeMod,
                FormatCode = format,
            });

        }
        return rows;
    }
    
    private List<string?> ParseDataRowMessage(byte[] payload)
    {
        List<string?> row = new List<string>();
        var ms = new MemoryStream(payload);
        var reader = new BinaryReader(ms, Encoding.UTF8);

        short fieldCount = Helper.ReadInt16(reader);
        for (int i = 0; i < fieldCount; i++)
        {
            var len = Helper.ReadInt32(reader);
            if (len == -1)
            {
                row.Add(null);
            }
            else
            {
                byte[] valBytes = reader.ReadBytes(len);
                string val = Encoding.UTF8.GetString(valBytes);
                row.Add(val);
            }

        }

        return row;

    }
}
