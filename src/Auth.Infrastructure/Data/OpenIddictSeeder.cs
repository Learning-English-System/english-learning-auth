using BuildingBlocks.Security.Constants;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Infrastructure.Data;

public static class OpenIddictSeeder
{
    public static async Task SeedAsync(IServiceProvider serviceProvider)
    {
        var scopeManager = serviceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var appManager = serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Seed scopes
        string[] scopes =
        [
            Scopes.OpenId,
            Scopes.Profile,
            Scopes.Email,
            Scopes.OfflineAccess,
            "english-learning-api",
            SecurityConstants.Scopes.InternalProfileRead,
            SecurityConstants.Scopes.InternalLearningRead,
            SecurityConstants.Scopes.InternalLearningWrite,
            SecurityConstants.Scopes.InternalAiInvoke,
            SecurityConstants.Scopes.InternalTestRead,
            SecurityConstants.Scopes.InternalAuthRead
        ];

        foreach (var scope in scopes)
        {
            if (await scopeManager.FindByNameAsync(scope) == null)
            {
                await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = scope,
                    DisplayName = $"{scope} scope"
                });
            }
        }

        const string webClientId = "english-learning-web";
        var existingWeb = await appManager.FindByClientIdAsync(webClientId);
        if (existingWeb == null)
        {
            await appManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = webClientId,
                ClientType = ClientTypes.Public,
                DisplayName = "English Learning Web Client",
                RedirectUris =
                {
                    new Uri("http://localhost:3000/callback"),
                    new Uri("http://localhost:8080/callback")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("http://localhost:3000/"),
                    new Uri("http://localhost:8080/")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.GrantTypes.Password,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + Scopes.OpenId,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Permissions.Prefixes.Scope + "english-learning-api"
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }
        else if (!await appManager.HasPermissionAsync(existingWeb, Permissions.GrantTypes.Password))
        {
            var descriptor = new OpenIddictApplicationDescriptor();
            await appManager.PopulateAsync(descriptor, existingWeb);
            descriptor.Permissions.Add(Permissions.GrantTypes.Password);
            await appManager.UpdateAsync(existingWeb, descriptor);
        }

        // Seed Confidential service clients
        var services = new (string ClientId, string Secret, string[] AllowedScopes)[]
        {
            ("profile-service", "profile-service-secret-2026", [SecurityConstants.Scopes.InternalAuthRead]),
            ("learning-service", "learning-service-secret-2026", [SecurityConstants.Scopes.InternalAiInvoke]),
            ("ai-service", "ai-service-secret-2026", []),
            ("test-service", "test-service-secret-2026", [SecurityConstants.Scopes.InternalLearningRead, SecurityConstants.Scopes.InternalAiInvoke])
        };

        foreach (var svc in services)
        {
            if (await appManager.FindByClientIdAsync(svc.ClientId) == null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = svc.ClientId,
                    ClientSecret = svc.Secret,
                    ClientType = ClientTypes.Confidential,
                    DisplayName = $"{svc.ClientId} internal client",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.ClientCredentials
                    }
                };

                foreach (var sc in svc.AllowedScopes)
                {
                    descriptor.Permissions.Add(Permissions.Prefixes.Scope + sc);
                }

                await appManager.CreateAsync(descriptor);
            }
        }
    }
}
