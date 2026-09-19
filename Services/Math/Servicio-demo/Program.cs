using EPPackage.Authentication.Domain.Defaults;
using EPPackage.Authentication.Domain.Options;
using EPPackage.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddAuthentication(GatewaySignatureDefaults.AuthenticationScheme)
    .AddScheme<GatewaySignatureAuthenticationOptions, GatewaySignatureAuthenticationHandler>(
        GatewaySignatureDefaults.AuthenticationScheme,
        options => builder.Configuration.GetSection("GatewaySignature").Bind(options));
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/", () => "Hello World!");

app.Run();
