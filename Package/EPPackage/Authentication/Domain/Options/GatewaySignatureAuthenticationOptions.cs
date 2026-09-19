using Microsoft.AspNetCore.Authentication;

namespace EPPackage.Authentication.Domain.Options;

public class GatewaySignatureAuthenticationOptions : AuthenticationSchemeOptions
{
    public string JwksUrl {get;set;} = string.Empty;
}
