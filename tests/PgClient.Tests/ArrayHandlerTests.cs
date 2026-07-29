using PgClient.Response;
using PgClient.Types.Handlers;
using Xunit;

namespace PgClient.Tests;

public class ArrayHandlerTests
{
    [Fact]
    public void Int4Array_TextRoundTrip()
    {
        var h = new ArrayHandler(PgOid.Int4Array, new Int4Handler());
        int[] value = { 1, 2, 3, 42 };
        var encoded = h.EncodeText(value);
        var decoded = (int[])h.ReadText(encoded);
        Assert.Equal(value, decoded);
    }

    [Fact]
    public void Int4Array_ReadsEmpty()
    {
        var h = new ArrayHandler(PgOid.Int4Array, new Int4Handler());
        var arr = (int[])h.ReadText(System.Text.Encoding.ASCII.GetBytes("{}"));
        Assert.Empty(arr);
    }

    [Fact]
    public void TextArray_HandlesNulls()
    {
        var h = new ArrayHandler(PgOid.TextArray, new TextHandler(PgOid.Text));
        var arr = (string?[])h.ReadText(System.Text.Encoding.UTF8.GetBytes("{\"a\",NULL,\"b\"}"));
        Assert.Equal(new[] { "a", null, "b" }, arr);
    }

    [Fact]
    public void TextArray_HandlesQuotedElements()
    {
        var h = new ArrayHandler(PgOid.TextArray, new TextHandler(PgOid.Text));
        var arr = (string?[])h.ReadText(System.Text.Encoding.UTF8.GetBytes("{\"hello world\",\"a,b\"}"));
        Assert.Equal(new[] { "hello world", "a,b" }, arr);
    }

    [Fact]
    public void TextArray_EncodesElementsWithSpecialChars()
    {
        var h = new ArrayHandler(PgOid.TextArray, new TextHandler(PgOid.Text));
        string[] input = { "plain", "has,comma", "has\"quote" };
        var bytes = h.EncodeText(input);
        var decoded = (string?[])h.ReadText(bytes);
        Assert.Equal(input, decoded);
    }
}
