using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using EPPackage.Authentication.Domain.Defaults;

namespace Servicio_demo.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = GatewaySignatureDefaults.AuthenticationScheme)]
public class ConsultaDemoController : ControllerBase
{
    [HttpGet]
    public ActionResult<string> Get()
    {
        return "3.141592653";
    }
}
