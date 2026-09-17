using System.Security.Cryptography;
using System.Text;

namespace ApiGateway.Middleware;

// Signs the inbound "OM-payload" header with the configured ECDSA private key
// and forwards the raw payload + signature as internal headers for downstream services.
public class GatewaySignerMiddleware
{
    private const string PayloadHeaderName = "OM-payload";
    private const string InternalPayloadHeaderName = "internal-payload";
    private const string InternalSignatureHeaderName = "internal-signature";

    private readonly RequestDelegate _next;
    private readonly ECDsa _ecdsa;

    public GatewaySignerMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _ecdsa = GatewaySignerKeyLoader.LoadFromConfiguration(configuration);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue(PayloadHeaderName, out var omPayload))
        {
            var payloadBytes = Encoding.UTF8.GetBytes(omPayload.ToString());
            var signatureBytes = _ecdsa.SignData(payloadBytes, HashAlgorithmName.SHA256);

            context.Request.Headers[InternalPayloadHeaderName] = Convert.ToBase64String(payloadBytes);
            context.Request.Headers[InternalSignatureHeaderName] = Convert.ToBase64String(signatureBytes);
        }

        await _next(context);
    }
}

public static class GatewaySignerMiddlewareExtensions
{
    public static IApplicationBuilder UseGatewaySigner(this IApplicationBuilder app)
        => app.UseMiddleware<GatewaySignerMiddleware>();
}
