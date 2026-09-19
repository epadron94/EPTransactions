using System.Text.Json.Serialization;
using EPPackage.Authentication.Domain.Entities;

namespace EPPackage.Authentication.Domain.Responses;

public class JwksResponse
{
    [JsonPropertyName("keys")]
    public List<JwkKey> Keys {get;set;} = new();
}
