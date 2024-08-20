using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace MinimalOtp.Core;

/// <summary>
/// Helper functions for the OTP generator
/// </summary>
internal static class OptPrimitives
{
    /// <summary>
    /// Truncates the hash to a 6-digit number according to RFC 4226
    /// </summary>
    /// <param name="hash"></param>
    /// <returns></returns>
    public static int TruncateHash(in ReadOnlySpan<byte> hash)
    {
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);
        
        return binary % 1_000_000;
    }
    
    /// <summary>
    /// Computes the HMAC hash
    /// </summary>
    /// <param name="hmac"></param>
    /// <param name="counter"></param>
    /// <param name="destination"></param>
    /// <param name="bytesWritten"></param>
    /// <returns></returns>
    public static bool ComputeHmacHash(HMAC hmac, long counter, in Span<byte> destination, out int bytesWritten)
    {
        Span<byte> counterBytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);
        
        return hmac.TryComputeHash(counterBytes, destination, out bytesWritten);
    }

    /// <summary>
    /// Creates a HMAC object based on the algorithm
    /// </summary>
    /// <param name="algorithm"></param>
    /// <param name="base32Secret"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static HMAC CreateHmacAlgorithm(HmacAlgorithm algorithm, string base32Secret) => algorithm switch
    {
        HmacAlgorithm.Sha1 => new HMACSHA1(GetBytesFromKey(base32Secret)),
        HmacAlgorithm.Sha256 => new HMACSHA256(GetBytesFromKey(base32Secret)),
        HmacAlgorithm.Sha512 => new HMACSHA512(GetBytesFromKey(base32Secret)),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
    };
    
    /// <summary>
    /// Extracts the bytes from the key
    /// </summary>
    /// <param name="base32Secret"></param>
    /// <returns></returns>
    private static byte[] GetBytesFromKey(string base32Secret) => Base32.FromBase32(base32Secret);
}