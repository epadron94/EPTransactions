using System.Security.Cryptography;
using ApiGateway.Middleware;
using Microsoft.AspNetCore.Mvc;

namespace ApiGateway.Controllers;

[ApiController]
[Route(".well-known")]
public class JwksController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public JwksController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpGet("/.well-known/jwks.json")]
    public IActionResult Get()
    {
        using var ecdsa = GatewaySignerKeyLoader.LoadFromConfiguration(_configuration);
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        var crv = GetCurveName(parameters.Curve);

        var jwk = new
        {
            kty = "EC",
            crv,
            x = Base64UrlEncode(parameters.Q.X!),
            y = Base64UrlEncode(parameters.Q.Y!),
            use = "sig",
            alg = GetAlgorithmName(crv),
            kid = "gateway-signer"
        };

        return Ok(new { keys = new[] { jwk } });
    }

    private static string GetCurveName(ECCurve curve)
    {
        if (curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value) return "P-256";
        if (curve.Oid.Value == ECCurve.NamedCurves.nistP384.Oid.Value) return "P-384";
        if (curve.Oid.Value == ECCurve.NamedCurves.nistP521.Oid.Value) return "P-521";
        return curve.Oid.FriendlyName ?? curve.Oid.Value ?? "unknown";
    }

    private static string GetAlgorithmName(string crv) => crv switch
    {
        "P-256" => "ES256",
        "P-384" => "ES384",
        "P-521" => "ES512",
        _ => "ES256"
    };

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
