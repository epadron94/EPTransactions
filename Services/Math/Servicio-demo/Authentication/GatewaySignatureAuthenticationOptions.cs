using Microsoft.AspNetCore.Authentication;

namespace Servicio_demo.Authentication;

public static class GatewaySignatureDefaults
{
    public const string AuthenticationScheme = "GatewaySignature";
}

public class GatewaySignatureAuthenticationOptions : AuthenticationSchemeOptions
{
    // URL of the ApiGateway's JWKS endpoint used to fetch the public verification key.
    public string JwksUrl { get; set; } = string.Empty;
}
