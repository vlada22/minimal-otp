// See https://aka.ms/new-console-template for more information

using MinimalOtp.Core;

var key = "ONSWG4TFOQ======"; // Base32 encoded secret key

var cts = new CancellationTokenSource();

var task = Task.Factory.StartNew(async () =>
{
    while (!cts.IsCancellationRequested)
    {
        var totp = OtpGenerator.GenerateTotp(key);
        var totp256 = OtpGenerator.GenerateTotp(key, algorithm: HmacAlgorithm.Sha256);
        var totp512 = OtpGenerator.GenerateTotp(key, algorithm: HmacAlgorithm.Sha512);

        Console.WriteLine($"TOTP: {totp} - {totp256} - {totp512} at {DateTimeOffset.Now.ToUnixTimeSeconds()}");

        await Task.Delay(1000);
    }
});

Console.WriteLine("Press any key to stop the TOTP generator");
Console.ReadKey();

cts.Cancel();
await task;



