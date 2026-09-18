using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Servicio_demo.Authentication;

// Verifies that "internal-payload" was signed by the ApiGateway's private key,
// using the matching public key published at Options.JwksUrl.
public class GatewaySignatureAuthenticationHandler : AuthenticationHandler<GatewaySignatureAuthenticationOptions>
{
    private const string PayloadHeaderName = "internal-payload";
    private const string SignatureHeaderName = "internal-signature";

    private readonly HttpClient _httpClient;

    public GatewaySignatureAuthenticationHandler(
        IOptionsMonitor<GatewaySignatureAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IHttpClientFactory httpClientFactory)
        : base(options, logger, encoder)
    {
        _httpClient = httpClientFactory.CreateClient(nameof(GatewaySignatureAuthenticationHandler));
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(PayloadHeaderName, out var payloadHeader) ||
            !Request.Headers.TryGetValue(SignatureHeaderName, out var signatureHeader))
        {
            return AuthenticateResult.Fail("Missing internal-payload/internal-signature headers.");
        }

        byte[] payloadBytes;
        byte[] signatureBytes;
        try
        {
            payloadBytes = Convert.FromBase64String(payloadHeader.ToString());
            signatureBytes = Convert.FromBase64String(signatureHeader.ToString());
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("internal-payload/internal-signature headers are not valid base64.");
        }

        ECDsa publicKey;
        try
        {
            publicKey = await GetPublicKeyAsync();
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail($"Unable to retrieve gateway signing key: {ex.Message}");
        }

        if (!publicKey.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256))
        {
            return AuthenticateResult.Fail("Signature verification failed.");
        }

        var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "ApiGateway") }, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }

    private async Task<ECDsa> GetPublicKeyAsync()
    {
        var jwks = await _httpClient.GetFromJsonAsync<JwksResponse>(Options.JwksUrl)
            ?? throw new InvalidOperationException("Empty JWKS response.");

        var jwk = jwks.Keys.FirstOrDefault()
            ?? throw new InvalidOperationException("No keys found in JWKS response.");

        var parameters = new ECParameters
        {
            Curve = CurveFromName(jwk.Crv),
            Q = new ECPoint
            {
                X = Base64UrlDecode(jwk.X),
                Y = Base64UrlDecode(jwk.Y)
            }
        };

        return ECDsa.Create(parameters);
    }

    private static ECCurve CurveFromName(string crv) => crv switch
    {
        "P-256" => ECCurve.NamedCurves.nistP256,
        "P-384" => ECCurve.NamedCurves.nistP384,
        "P-521" => ECCurve.NamedCurves.nistP521,
        _ => throw new NotSupportedException($"Unsupported curve '{crv}'.")
    };

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }

    private class JwksResponse
    {
        [JsonPropertyName("keys")]
        public List<JwkKey> Keys { get; set; } = new();
    }

    private class JwkKey
    {
        [JsonPropertyName("crv")]
        public string Crv { get; set; } = string.Empty;

        [JsonPropertyName("x")]
        public string X { get; set; } = string.Empty;

        [JsonPropertyName("y")]
        public string Y { get; set; } = string.Empty;
    }
}
