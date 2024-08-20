namespace MinimalOtp.Core;

public static class OtpGenerator
{
    /// <summary>
    /// Generates a TOTP token according to RFC 6238
    /// </summary>
    /// <param name="base32Secret">Shared secret base32 encoded</param>
    /// <param name="timeStep">The period T in seconds</param>
    /// <param name="algorithm">The HMAC algorithm to use</param>
    /// <param name="unixTime">The time to use for the token generation (default is 0 which is the current time)</param>
    /// <param name="otpLength">The length of the OTP token</param>
    /// <returns></returns>
    public static string GenerateTotp(string base32Secret, int timeStep = 30, HmacAlgorithm algorithm = HmacAlgorithm.Sha1, long unixTime = 0, int otpLength = 6)
    {
        // Calculate a counter based on the current time and the period T defined in RFC 6238
        var counter = (unixTime is 0 ? DateTimeOffset.Now.ToUnixTimeSeconds() : unixTime) / timeStep;
        
        // totp(k, t) = hotp(k, t) where t = (unixtime / period)
        return GenerateHotp(base32Secret, counter, algorithm, otpLength);
    }
    
    /// <summary>
    /// Generates a HOTP token according to RFC 4226
    /// </summary>
    /// <param name="base32Secret">Shared key base32 encoded</param>
    /// <param name="counter">The counter value</param>
    /// <param name="algorithm">The HMAC algorithm to use</param>
    /// <param name="otpLength">The length of the OTP token</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public static string GenerateHotp(string base32Secret, long counter, HmacAlgorithm algorithm = HmacAlgorithm.Sha1, int otpLength = 6)
    {
        // Create a HMAC object based on the algorithm
        using var hmac = OptPrimitives.CreateHmacAlgorithm(algorithm, base32Secret);
        
        // Compute the hash
        Span<byte> hash = stackalloc byte[hmac.HashSize / 8];
        if (!OptPrimitives.ComputeHmacHash(hmac, counter, hash, out _))
        {
            throw new InvalidOperationException("Failed to compute the HMAC hash");
        }
        
        // Truncate the hash to a 6-digit number according to RFC 4226
        var truncatedHash = OptPrimitives.TruncateHash(hash);
        
        return truncatedHash.ToString().PadLeft(otpLength, '0');
    }
    
    /// <summary>
    /// Validates a HOTP token
    /// </summary>
    /// <param name="base32Secret"></param>
    /// <param name="otp"></param>
    /// <param name="counter"></param>
    /// <param name="algorithm"></param>
    /// <param name="otpLength"></param>
    /// <returns></returns>
    public static bool ValidateHotp(string base32Secret, string otp, long counter, HmacAlgorithm algorithm = HmacAlgorithm.Sha1, int otpLength = 6)
    {
        var generatedOtp = GenerateHotp(base32Secret, counter, algorithm, otpLength);
        
        return otp == generatedOtp;
    }
    
    /// <summary>
    /// Validates a TOTP token
    /// </summary>
    /// <param name="base32Secret"></param>
    /// <param name="otp"></param>
    /// <param name="timeStep"></param>
    /// <param name="algorithm"></param>
    /// <param name="unixTime"></param>
    /// <param name="otpLength"></param>
    /// <returns></returns>
    public static bool ValidateTotp(string base32Secret, string otp, int timeStep = 30, HmacAlgorithm algorithm = HmacAlgorithm.Sha1, long unixTime = 0, int otpLength = 6)
    {
        var generatedOtp = GenerateTotp(base32Secret, timeStep, algorithm, unixTime, otpLength);
        
        return otp == generatedOtp;
    }
}