using System.Text.Json.Serialization;

namespace EPPackage.Authentication.Domain.Entities;

public class JwkKey
{
    [JsonPropertyName("crv")]
    public required string Crv {get;set;}

    [JsonPropertyName("x")]
    public required string X {get;set;}

    [JsonPropertyName("y")]
    public required string Y {get;set;}
    [JsonPropertyName("kid")]
    public required string Kid {get;set;}
}
