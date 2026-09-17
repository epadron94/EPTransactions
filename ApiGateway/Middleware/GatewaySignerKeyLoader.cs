using System.Security.Cryptography;

namespace ApiGateway.Middleware;

public static class GatewaySignerKeyLoader
{
    public static ECDsa LoadFromConfiguration(IConfiguration configuration)
    {
        var privateKeyPath = configuration["GatewaySigner:PrivateKeyPath"]
            ?? throw new InvalidOperationException("GatewaySigner:PrivateKeyPath is not configured.");

        var pem = File.ReadAllText(privateKeyPath);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa;
    }
}
