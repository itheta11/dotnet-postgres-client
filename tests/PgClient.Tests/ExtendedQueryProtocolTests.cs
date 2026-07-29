using System.Buffers.Binary;
using PgClient.Query;
using PgClient.Response;
using PgClient.Types;
using Xunit;

namespace PgClient.Tests;

/// Verifies the wire framing produced by ExtendedQueryProtocol writers.
public class ExtendedQueryProtocolTests
{
    [Fact]
    public void WriteSync_ProducesFiveByteFrame()
    {
        using var ms = new MemoryStream();
        ExtendedQueryProtocol.WriteSync(ms);
        var bytes = ms.ToArray();
        Assert.Equal(5, bytes.Length);
        Assert.Equal((byte)'S', bytes[0]);
        Assert.Equal(4, BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(1, 4)));
    }

    [Fact]
    public void WriteParse_LayoutMatchesSpec()
    {
        using var ms = new MemoryStream();
        var parameters = new List<PgParameter>
        {
            PgParameter.Int4(1),
            PgParameter.Text("x"),
        };

        ExtendedQueryProtocol.WriteParse(ms, "stmt1", "SELECT $1, $2", parameters);
        var bytes = ms.ToArray();

        Assert.Equal((byte)'P', bytes[0]);
        int bodyLen = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(1, 4));
        Assert.Equal(bytes.Length - 1, bodyLen);

        // stmt cstring
        int pos = 5;
        int nulPos = Array.IndexOf(bytes, (byte)0, pos);
        Assert.Equal("stmt1", System.Text.Encoding.UTF8.GetString(bytes.AsSpan(pos, nulPos - pos)));
        pos = nulPos + 1;

        // sql cstring
        nulPos = Array.IndexOf(bytes, (byte)0, pos);
        Assert.Equal("SELECT $1, $2", System.Text.Encoding.UTF8.GetString(bytes.AsSpan(pos, nulPos - pos)));
        pos = nulPos + 1;

        // param count
        short paramCount = BinaryPrimitives.ReadInt16BigEndian(bytes.AsSpan(pos, 2));
        Assert.Equal(2, paramCount);
        pos += 2;

        Assert.Equal(PgOid.Int4, (uint)BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(pos, 4)));
        pos += 4;
        Assert.Equal(PgOid.Text, (uint)BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(pos, 4)));
    }

    [Fact]
    public void WriteBind_EmitsResultFormatText()
    {
        using var ms = new MemoryStream();
        var parameters = new List<PgParameter> { PgParameter.Int4(42) };
        byte[]?[] encoded = new byte[]?[] { parameters[0].Encode(PgTypeRegistry.Default) };
        ExtendedQueryProtocol.WriteBind(ms, portalName: "", statementName: "", parameters, encoded);
        var bytes = ms.ToArray();

        Assert.Equal((byte)'B', bytes[0]);

        // Last 4 bytes: result format count (=1) + Text (=0)
        int end = bytes.Length;
        short resultCount = BinaryPrimitives.ReadInt16BigEndian(bytes.AsSpan(end - 4, 2));
        short resultFmt = BinaryPrimitives.ReadInt16BigEndian(bytes.AsSpan(end - 2, 2));
        Assert.Equal(1, resultCount);
        Assert.Equal((short)PgFormatCode.Text, resultFmt);
    }

    [Fact]
    public void WriteBind_NullParameter_EncodedAsNegativeOneLength()
    {
        using var ms = new MemoryStream();
        var parameters = new List<PgParameter> { PgParameter.Null(PgOid.Int4) };
        byte[]?[] encoded = new byte[]?[] { null };
        ExtendedQueryProtocol.WriteBind(ms, "", "", parameters, encoded);
        var bytes = ms.ToArray();

        // Scan forward to find the -1 length. It should exist somewhere after the two
        // cstrings + format array + param count.
        bool found = false;
        for (int i = 0; i <= bytes.Length - 4; i++)
        {
            if (BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(i, 4)) == -1)
            {
                found = true; break;
            }
        }
        Assert.True(found, "Expected a -1 length prefix indicating SQL NULL.");
    }

    [Fact]
    public void WriteExecute_HasCorrectHeaderAndMaxRows()
    {
        using var ms = new MemoryStream();
        ExtendedQueryProtocol.WriteExecute(ms, "portal1", maxRows: 100);
        var bytes = ms.ToArray();
        Assert.Equal((byte)'E', bytes[0]);
        // last 4 bytes = maxRows
        int mr = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(bytes.Length - 4, 4));
        Assert.Equal(100, mr);
    }
}
