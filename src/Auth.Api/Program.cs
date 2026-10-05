using Auth.Application.Extensions;
using Auth.Domain.Entities;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Extensions;
using BuildingBlocks.Observability;
using BuildingBlocks.Security.Constants;
using BuildingBlocks.Web.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Logging
builder.Logging.AddCustomStructuredLogging(builder.Environment);

// Core services
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Shared building blocks
builder.Services.AddBuildingBlocksWeb();

// Auth domain layers
builder.Services.AddAuthInfrastructure(builder.Configuration);
builder.Services.AddAuthApplication();

// CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:3000", "http://localhost:8080")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// Rate limiting
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("auth-policy", opt =>
    {
        opt.PermitLimit = 50;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 0;
    });
});

var app = builder.Build();

// Run DB migrations and seed initial roles
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<Role>>();

    // Migrate database
    await dbContext.Database.MigrateAsync();

    // Ensure Learner & Admin roles exist
    if (!await roleManager.RoleExistsAsync(SecurityConstants.Roles.Learner))
    {
        await roleManager.CreateAsync(new Role(SecurityConstants.Roles.Learner));
    }

    if (!await roleManager.RoleExistsAsync(SecurityConstants.Roles.Admin))
    {
        await roleManager.CreateAsync(new Role(SecurityConstants.Roles.Admin));
    }

    // Seed OpenIddict scopes & clients
    await OpenIddictSeeder.SeedAsync(scope.ServiceProvider);
}

if (args.Contains("--migrate"))
{
    app.Logger.LogInformation("Database migration complete. Exiting (--migrate flag present).");
    return;
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseBuildingBlocksWeb();
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

// Required for WebApplicationFactory in integration tests
public partial class Program { }
