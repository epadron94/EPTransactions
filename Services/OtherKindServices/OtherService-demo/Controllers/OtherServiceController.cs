using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using EPPackage.Authentication;
using EPPackage.Authentication.Domain.Defaults;
namespace OtherService_demo.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = GatewaySignatureDefaults.AuthenticationScheme)]
public class OtherServiceController : ControllerBase
{
    [HttpGet]
    public ActionResult<string> Get()
    {
        return "Hello from OtherService!";
    }
}
