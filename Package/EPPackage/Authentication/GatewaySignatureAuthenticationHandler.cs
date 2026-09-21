using EPPackage.Authentication.Domain.Responses;
using EPPackage.Authentication.Domain.Options;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using EPPackage.Utilities;

namespace EPPackage.Authentication;

public class GatewaySignatureAuthenticationHandler : AuthenticationHandler<GatewaySignatureAuthenticationOptions>
{
    private const string PayloadHeaderName = "internal-payload";
    private const string SignatureHeaderName = "internal-signature";
    private readonly HttpClient httpClient;
    public GatewaySignatureAuthenticationHandler(IOptionsMonitor<GatewaySignatureAuthenticationOptions> options,
                                                ILoggerFactory logger,
                                                UrlEncoder encoder,
                                                IHttpClientFactory httpClientFactory)
                                                :base(options, logger, encoder)
    {
        httpClient = httpClientFactory.CreateClient(nameof(GatewaySignatureAuthenticationHandler));
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
            var endpoint = Request.Path.Value?.Split("/")[2].ToLower();
            publicKey = await GetPublicKeyAsync(endpoint!);
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

    private async Task<ECDsa> GetPublicKeyAsync(string endpoint)
    {
        var jwks = await httpClient.GetFromJsonAsync<JwksResponse>(Options.JwksUrl)
            ?? throw new InvalidOperationException("Empty JWKS response");
        
        var keyName = EPUtilities.EndpointKeys[endpoint];
        var jwk = jwks.Keys.FirstOrDefault(k => k.Kid == keyName)
            ?? throw new InvalidOperationException("No keys found");
        
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Base64UrlDecode(jwk.X),
                Y = Base64UrlDecode(jwk.Y)
            }
        };
        return ECDsa.Create(parameters);
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }
}

