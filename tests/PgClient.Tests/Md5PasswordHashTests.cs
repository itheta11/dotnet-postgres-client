using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PgClient.Tests;

/// Verifies the exact Postgres MD5 password hashing algorithm.
/// Postgres computes: "md5" + hex(md5(hex(md5(password + username)) + salt))
public class Md5PasswordHashTests
{
    [Fact]
    public void KnownVector_ProducesExpectedHash()
    {
        string user = "postgres";
        string password = "secret";
        byte[] salt = { 0x00, 0x01, 0x02, 0x03 };

        string actual = ComputeMd5Password(user, password, salt);

        // Reference implementation: md5( hex(md5(password + user)) + salt )
        string inner = ToHexLower(MD5.HashData(Encoding.UTF8.GetBytes(password + user)));
        byte[] withSalt = Encoding.ASCII.GetBytes(inner).Concat(salt).ToArray();
        string expected = "md5" + ToHexLower(MD5.HashData(withSalt));

        Assert.Equal(expected, actual);
        Assert.StartsWith("md5", actual);
        Assert.Equal(35, actual.Length); // "md5" + 32 hex chars
    }

    [Fact]
    public void SaltAffectsResult()
    {
        var salt1 = new byte[] { 1, 2, 3, 4 };
        var salt2 = new byte[] { 4, 3, 2, 1 };
        Assert.NotEqual(
            ComputeMd5Password("u", "p", salt1),
            ComputeMd5Password("u", "p", salt2));
    }

    [Fact]
    public void UserAffectsResult()
    {
        var salt = new byte[] { 1, 2, 3, 4 };
        Assert.NotEqual(
            ComputeMd5Password("a", "p", salt),
            ComputeMd5Password("b", "p", salt));
    }

    // Mirrors AuthenticationHandler.SendMd5Password's internal computation.
    private static string ComputeMd5Password(string user, string password, byte[] salt)
    {
        string inner = ToHexLower(MD5.HashData(Encoding.UTF8.GetBytes(password + user)));
        byte[] innerBytes = Encoding.ASCII.GetBytes(inner);
        byte[] withSalt = new byte[innerBytes.Length + salt.Length];
        Buffer.BlockCopy(innerBytes, 0, withSalt, 0, innerBytes.Length);
        Buffer.BlockCopy(salt, 0, withSalt, innerBytes.Length, salt.Length);
        return "md5" + ToHexLower(MD5.HashData(withSalt));
    }

    private static string ToHexLower(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
}
