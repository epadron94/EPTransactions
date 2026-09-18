using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using ApiGateway.Middleware;
using VaultSharp;
using Microsoft.Extensions.Options;
using VaultSharp.V1.AuthMethods.AppRole;
using VaultSharp.V1.AuthMethods;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("ocelot.json", optional: false, reloadOnChange: true);
builder.Services.AddOcelot(builder.Configuration);
builder.Services.AddControllers();

builder.Services.Configure<VaultOptions>(builder.Configuration.GetSection("Vault"));

builder.Services.AddSingleton<IVaultClient>(sp =>
{
    var opts = sp.GetRequiredService<IOptions<VaultOptions>>().Value;

    var secretId = Environment.GetEnvironmentVariable("BAO_SECRET_ID")
        ?? throw new InvalidOperationException("BAO_SECRET_ID not set");

    IAuthMethodInfo authMethod = new AppRoleAuthMethodInfo(opts.RoleId, secretId);
    var settings = new VaultClientSettings(opts.Address, authMethod);
    return new VaultClient(settings);
});
builder.Services.AddSingleton<IGatewaySignerKeyProvider, VaultGatewaySignerKeyProvider>();   


var app = builder.Build();
app.UseRouting();

app.MapWhen(ctx =>
    ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch =>
    {
        branch.UseRouting();
        branch.UseEndpoints(e =>
        {
            e.MapControllers();
        });
    }
);

app.MapControllers();
app.UseGatewaySigner();

await app.UseOcelot();

app.Run();
