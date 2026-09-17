using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace ApiGateway.Middleware;

public interface IGatewaySignerKeyProvider
{
    Task<ECDsa> GetSigningKeyAsync(CancellationToken ct = default);
    Task<(string Kid, ECDsa PublicKey)> GetPublicKeyAsync(CancellationToken ct = default);
}

public class VaultGatewaySignerKeyprovider : IGatewaySignerKeyProvider
{
    private readonly IVaultClient vaultClient;
    private readonly VaultOptions vaultOptions;
    private readonly string serviceName;

    private ECDsa? cachedKey;
    private string? cachedKid;
    private DateTimeOffset cacheExpiresAt = DateTimeOffset.MinValue;
    private readonly TimeSpan cacheDuration = TimeSpan.FromMinutes(5);
    private readonly SemaphoreSlim _lock = new(1,1);

    public VaultGatewaySignerKeyprovider(IVaultClient _vaultClient,
                                         IOptions<VaultOptions> _vaultOptions,
                                         IConfiguration configuration)
    {
        vaultClient = _vaultClient;
        vaultOptions = _vaultOptions.Value;
        serviceName =  configuration["GatewaySigner:ServiceName"]
            ?? throw new InvalidOperationException("GatewaySigner:ServiceName is not configured.");
    }

    public async Task<(string Kid, ECDsa PublicKey)> GetPublicKeyAsync(CancellationToken ct = default)
    {
        await 
    }

    public Task<ECDsa> GetSigningKeyAsync(CancellationToken ct = default)
    {
        throw new NotImplementedException();
    }

    private async Task EnsureLoadedAsync(CancellationToken ct)
    {
        if(cachedKey != null && DateTimeOffset.UtcNow < cacheExpiresAt)
        return;

        await _lock.WaitAsync(ct);
        try
        {
            if(cachedKey != null && DateTimeOffset.UtcNow < cacheExpiresAt)
            return;

            Secret<SecretData> secret = await vaultClient.V1.Secrets.KeyValue.V2
            .ReadSecretAsync(path: $"{vaultOptions.SecretPathPrefix}/{serviceName}",
                             mountPoint: vaultOptions.MounthPath);

            var pem = (string)secret.Data.Data["private_key_pem"];
            var kid = (string)secret.Data.Data["kid"];
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);

            cachedKey?.Dispose();
            cachedKey =  ecdsa;
            cachedKid = kid;
            cacheExpiresAt = DateTimeOffset.UtcNow.Add(cacheDuration);
        }
        finally
        {
            _lock.Release();
        }
    }
}