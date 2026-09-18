using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace ApiGateway.Middleware;

public interface IGatewaySignerKeyProvider
{
    Task<ECDsa> GetSigningKeyAsync(CancellationToken ct = default);
    Task<(string Kid, ECDsa PublicKey)> GetPublicKeyAsync(CancellationToken ct = default);
}

public class VaultGatewaySignerKeyProvider : IGatewaySignerKeyProvider
{
    private readonly IVaultClient vaultClient;
    private readonly VaultOptions vaultOptions;
    private readonly string serviceName;

    private ECDsa? cachedKey;
    private string? cachedKid;
    private DateTimeOffset cacheExpiresAt = DateTimeOffset.MinValue;
    private readonly TimeSpan cacheDuration = TimeSpan.FromMinutes(5);
    private readonly SemaphoreSlim _lock = new(1,1);

    public VaultGatewaySignerKeyProvider(IVaultClient _vaultClient,
                                        IOptions<VaultOptions> _vaultOptions,
                                        IConfiguration configuration)
    {
        vaultClient = _vaultClient;
        vaultOptions = _vaultOptions.Value;
        serviceName =  configuration["GatewaySigner:ServiceName"]
            ?? throw new InvalidOperationException("GatewaySigner:ServiceName is not configured.");
    }

    public async Task<(string, ECDsa)> GetPublicKeyAsync(CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct);
        return (cachedKid!, cachedKey!);
    }

    public async Task<ECDsa> GetSigningKeyAsync(CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct);
        return cachedKey!;
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
                            mountPoint: vaultOptions.MountPath);

            var pem = ((JsonElement)secret.Data.Data["private_key_pem"]).GetString()
                ?? throw new InvalidOperationException("private_key_pem missing");
            
            var kid = ((JsonElement)secret.Data.Data["kid"]).GetString()
                ?? throw new InvalidOperationException("kid is missing");
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