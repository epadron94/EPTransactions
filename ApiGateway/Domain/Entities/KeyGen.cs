using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace ApiGateway.Domain.Entities;

public class KeyGen
{
    //[JsonPropertyName("kid")]
    public required string Kid {get;set;}
    //[JsonPropertyName("key")]
    public required ECDsa Key {get;set;}

}
