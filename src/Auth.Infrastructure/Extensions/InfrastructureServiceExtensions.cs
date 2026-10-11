using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Email;
using Auth.Infrastructure.Outbox;
using BuildingBlocks.Messaging.Outbox;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Infrastructure.Extensions;

public static class InfrastructureServiceExtensions
{
    public static IServiceCollection AddAuthInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        string connectionString = configuration.GetConnectionString("AuthDb")
            ?? configuration["AUTH_DB_CONNECTION"]
            ?? "Server=localhost,1433;Database=AuthDb;User Id=sa;Password=YourStrong@Passw0rd!2026;TrustServerCertificate=True;";

        services.AddDbContext<AuthDbContext>(options =>
        {
            options.UseSqlServer(connectionString);
            options.UseOpenIddict();
        });

        services.AddScoped<IAuthDbContext>(sp => sp.GetRequiredService<AuthDbContext>());

        services.AddIdentity<User, Role>(options =>
        {
            options.Password.RequiredLength = 12;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireUppercase = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireDigit = false;
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedEmail = true;
        })
        .AddEntityFrameworkStores<AuthDbContext>()
        .AddDefaultTokenProviders();

        services.AddScoped<IEmailSenderService, MailpitEmailSender>();
        services.AddScoped<IOutboxRepository, SqlOutboxRepository>();

        services.Configure<BuildingBlocks.Messaging.Kafka.KafkaProducerConfig>(options =>
        {
            var section = configuration.GetSection("Kafka");
            options.BootstrapServers = section["BootstrapServers"]
                ?? configuration["KAFKA_BOOTSTRAP_SERVERS"]
                ?? "localhost:9092";
            options.ClientId = section["ClientId"] ?? "auth-service-producer";
        });

        services.AddSingleton<BuildingBlocks.Messaging.Kafka.IEventPublisher, BuildingBlocks.Messaging.Kafka.KafkaEventPublisher>();
        services.AddSingleton<BuildingBlocks.Messaging.Outbox.OutboxPublisherWorker>();
        services.AddHostedService(sp => sp.GetRequiredService<BuildingBlocks.Messaging.Outbox.OutboxPublisherWorker>());

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<AuthDbContext>();
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetTokenEndpointUris("/connect/token")
                       .SetUserInfoEndpointUris("/connect/userinfo")
                       .SetRevocationEndpointUris("/connect/revoke");

                options.AllowAuthorizationCodeFlow()
                       .RequireProofKeyForCodeExchange()
                       .AllowRefreshTokenFlow()
                       .AllowClientCredentialsFlow()
                       .AllowPasswordFlow();

                // Produce signed JWTs as specified in Section 3.2
                options.DisableAccessTokenEncryption();

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));
                options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));
                options.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5));

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.UseAspNetCore()
                       .DisableTransportSecurityRequirement()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserInfoEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        services.Configure<Microsoft.AspNetCore.Authentication.AuthenticationOptions>(options =>
        {
            options.DefaultAuthenticateScheme = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
        });

        return services;
    }
}
