using System.Security.Cryptography;
using System.Text.Json;
using ApiGateway.Domain.Entities;
using Microsoft.Extensions.Options;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace ApiGateway.Middleware;

public interface IGatewaySignerKeyProvider
{
    //Serve to GatewaySignerMiddleware to get a single auth key
    Task<ECDsa> GetSigningKeyAsync(string kid, CancellationToken ct = default);
    //SErve to /.well-known/jwks.json public endpoint
    Task<List<KeyGen>> GetPublicKeysAsync(CancellationToken ct = default);
}

public class VaultGatewaySignerKeyProvider : IGatewaySignerKeyProvider
{
    private readonly IVaultClient vaultClient;
    private readonly VaultOptions vaultOptions;
    private readonly string serviceName;

    private List<KeyGen> cachedKeys = new();
    //private ECDsa? cachedKey;
    //private string? cachedKid;
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

    public async Task<List<KeyGen>> GetPublicKeysAsync(CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct);
        return cachedKeys;
    }

    public async Task<ECDsa> GetSigningKeyAsync(string kid,CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct);
        var cachedkey = cachedKeys.FirstOrDefault(k => k.Kid == kid)?.Key;
        return cachedkey!;
    }

    private async Task EnsureLoadedAsync(CancellationToken ct)
    {
        if(cachedKeys.Count > 0 && DateTimeOffset.UtcNow < cacheExpiresAt)
        return;

        await _lock.WaitAsync(ct);
        try
        {
            if(cachedKeys.Count > 0 && DateTimeOffset.UtcNow < cacheExpiresAt)
            return;

            var secretsList = await vaultClient.V1.Secrets.KeyValue.V2
            .ReadSecretPathsAsync(path: $"{vaultOptions.SecretPathPrefix}",
                            mountPoint: vaultOptions.MountPath);

            var newKeys = new List<KeyGen>();

            foreach(var keyName in secretsList.Data.Keys)
            {
                var secret = await vaultClient.V1.Secrets.KeyValue.V2
                    .ReadSecretAsync(path: $"{vaultOptions.SecretPathPrefix}/{keyName}",
                                    mountPoint: vaultOptions.MountPath);

                var pem = ((JsonElement)secret.Data.Data["private_key_pem"]).GetString()
                    ?? throw new InvalidOperationException("private key missing");

                var kid = ((JsonElement)secret.Data.Data["kid"]).GetString()
                    ?? throw new InvalidOperationException("kid missing");

                var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(pem);
                var x = new KeyGen { Kid = kid, Key = ecdsa };
                newKeys.Add(x);
            }

            foreach(var oldKey in cachedKeys)
            {
                oldKey.Key.Dispose();
            }

            cachedKeys = newKeys;
            cacheExpiresAt = DateTimeOffset.UtcNow.Add(cacheDuration);
        }
        finally
        {
            _lock.Release();
        }
    }
}