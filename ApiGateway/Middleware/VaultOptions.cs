namespace ApiGateway.Middleware;

public class VaultOptions
{
    public required string Address {get;set;}
    public required string MounthPath {get;set;}
    public required string SecretPathPrefix {get;set;}
    public required string RoleId {get;set;}
}