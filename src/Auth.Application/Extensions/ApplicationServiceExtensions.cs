using Auth.Application.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Application.Extensions;

public static class ApplicationServiceExtensions
{
    public static IServiceCollection AddAuthApplication(this IServiceCollection services)
    {
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<ISessionService, SessionService>();
        services.AddScoped<IRiskEngineService, RiskEngineService>();
        return services;
    }
}
