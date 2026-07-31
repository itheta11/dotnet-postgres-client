#if !NET9_0_OR_GREATER
namespace PgClient.Utilities;

/// Polyfills for APIs missing on target frameworks below .NET 9.
internal static class HexPolyfill
{
    private static ReadOnlySpan<char> LowerHex => "0123456789abcdef";

    public static string ToHexStringLower(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return string.Empty;
        Span<char> chars = bytes.Length <= 256
            ? stackalloc char[bytes.Length * 2]
            : new char[bytes.Length * 2];
        var lut = LowerHex;
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            chars[i * 2] = lut[b >> 4];
            chars[i * 2 + 1] = lut[b & 0xF];
        }
        return new string(chars);
    }

    public static string ToHexStringLower(byte[] bytes)
        => ToHexStringLower(bytes.AsSpan());
}
#endif
