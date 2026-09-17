using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using ApiGateway.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("ocelot.json", optional: false, reloadOnChange: true);
builder.Services.AddOcelot(builder.Configuration);
builder.Services.AddControllers();

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
