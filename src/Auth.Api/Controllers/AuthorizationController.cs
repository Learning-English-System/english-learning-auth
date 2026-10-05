using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using BuildingBlocks.Security.Constants;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Api.Controllers;

[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IAuthDbContext _dbContext;
    private readonly IEmailSenderService _emailSender;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IAuthDbContext dbContext,
        IEmailSenderService emailSender,
        ILogger<AuthorizationController> logger)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _userManager = userManager;
        _signInManager = signInManager;
        _dbContext = dbContext;
        _emailSender = emailSender;
        _logger = logger;
    }

    [HttpPost("~/connect/token")]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            return await HandleClientCredentialsGrant(request);
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            return await HandleAuthorizationCodeGrant();
        }

        if (request.IsRefreshTokenGrantType())
        {
            return await HandleRefreshTokenGrant();
        }

        if (request.IsPasswordGrantType())
        {
            return await HandlePasswordGrant(request);
        }

        return BadRequest(new OpenIddictResponse
        {
            Error = Errors.UnsupportedGrantType,
            ErrorDescription = "The specified grant type is not supported."
        });
    }

    private async Task<IActionResult> HandleClientCredentialsGrant(OpenIddictRequest request)
    {
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("The application details cannot be found.");

        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.AddClaim(Claims.Subject, request.ClientId!);
        identity.AddClaim(Claims.Name, (await _applicationManager.GetDisplayNameAsync(application)) ?? string.Empty);

        var scopes = request.GetScopes();
        identity.SetScopes(scopes);
        identity.SetResources("english-learning-api");

        foreach (var claim in identity.Claims)
        {
            claim.SetDestinations(Destinations.AccessToken);
        }

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> HandlePasswordGrant(OpenIddictRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Username ?? string.Empty);
        if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password ?? string.Empty))
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The email or password is incorrect."
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Email verification gate
        if (!user.EmailConfirmed)
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Email address has not been verified."
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (user.Status == UserStatus.Disabled)
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User account is disabled."
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var principal = await CreateUserPrincipalAsync(user, request.GetScopes());

        // Create or update Session and Refresh Token Family
        await CreateUserSessionAndRefreshFamilyAsync(user, principal);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> HandleAuthorizationCodeGrant()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var user = await _userManager.FindByIdAsync(result.Principal?.GetClaim(Claims.Subject) ?? string.Empty);

        if (user == null)
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (!user.EmailConfirmed)
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Email address has not been verified."
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var principal = await CreateUserPrincipalAsync(user, result.Principal!.GetScopes());
        await CreateUserSessionAndRefreshFamilyAsync(user, principal);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> HandleRefreshTokenGrant()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        string userIdStr = result.Principal?.GetClaim(Claims.Subject) ?? string.Empty;
        var user = await _userManager.FindByIdAsync(userIdStr);

        if (user == null || user.Status == UserStatus.Disabled)
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User is no longer active."
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Verify security stamp
        if (!await _signInManager.CanSignInAsync(user))
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var principal = await CreateUserPrincipalAsync(user, result.Principal!.GetScopes());

        // Refresh token rotation & reuse detection
        string? familyIdClaim = result.Principal?.GetClaim("rt_family_id");
        string? presentedHashClaim = result.Principal?.GetClaim("rt_token_hash");

        if (Guid.TryParse(familyIdClaim, out var familyId))
        {
            var family = await _dbContext.RefreshTokenFamilies
                .FirstOrDefaultAsync(f => f.Id == familyId);

            bool isReused = family == null 
                || family.IsRevoked 
                || (presentedHashClaim != null && presentedHashClaim == family.PreviousTokenHash)
                || (presentedHashClaim != null && presentedHashClaim != family.TokenHash);

            if (isReused)
            {
                _logger.LogWarning("Refresh token reuse detected for user {UserId}", user.Id);

                if (family != null)
                {
                    family.RevokedAt = DateTimeOffset.UtcNow;
                    family.RevocationReason = "TokenReuseDetected";
                }

                var secEvent = new SecurityEvent
                {
                    UserId = user.Id,
                    EventType = "RefreshTokenReuseDetected",
                    SessionId = family?.SessionId,
                    RiskScore = 90,
                    MetadataJson = $"{{\"familyId\":\"{familyId}\"}}"
                };
                await _dbContext.SecurityEvents.AddAsync(secEvent);
                await _dbContext.SaveChangesAsync();

                try
                {
                    await _emailSender.SendSecurityAlertAsync(
                        user.Email!,
                        "Suspicious refresh token activity",
                        "We detected suspicious repeated token usage on your account. Sessions have been secured.");
                }
                catch { }

                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Refresh token reuse detected. Access revoked."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // Rotate token hash
            string newTokenHash = ComputeHash(Guid.NewGuid().ToString("N"));
            family.PreviousTokenHash = family.TokenHash;
            family.TokenHash = newTokenHash;
            family.ExpiresAt = DateTimeOffset.UtcNow.AddHours(24);

            await _dbContext.SaveChangesAsync();

            var identity = (ClaimsIdentity)principal.Identity!;
            var rtFamilyClaim = new Claim("rt_family_id", family.Id.ToString());
            rtFamilyClaim.SetDestinations(Destinations.AccessToken);
            identity.AddClaim(rtFamilyClaim);

            var rtHashClaim = new Claim("rt_token_hash", newTokenHash);
            rtHashClaim.SetDestinations(Destinations.AccessToken);
            identity.AddClaim(rtHashClaim);
        }

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!result.Succeeded)
        {
            return Challenge(IdentityConstants.ApplicationScheme);
        }

        var user = await _userManager.GetUserAsync(result.Principal)
            ?? throw new InvalidOperationException("User could not be retrieved.");

        var principal = await CreateUserPrincipalAsync(user, request.GetScopes());
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/userinfo")]
    [Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!result.Succeeded)
        {
            return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var user = await _userManager.FindByIdAsync(result.Principal?.GetClaim(Claims.Subject) ?? string.Empty);
        if (user == null)
        {
            return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id.ToString(),
            [Claims.Email] = user.Email ?? string.Empty,
            [Claims.EmailVerified] = user.EmailConfirmed
        };

        var roles = await _userManager.GetRolesAsync(user);
        if (roles.Count > 0)
        {
            claims[Claims.Role] = roles.ToArray();
        }

        return Ok(claims);
    }

    private async Task<ClaimsPrincipal> CreateUserPrincipalAsync(User user, IEnumerable<string> requestedScopes)
    {
        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.AddClaim(Claims.Subject, user.Id.ToString());
        identity.AddClaim(Claims.Email, user.Email ?? string.Empty);
        identity.AddClaim(Claims.Name, user.UserName ?? string.Empty);

        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            identity.AddClaim(Claims.Role, role);
        }

        // Set scopes & resources
        var scopes = requestedScopes.ToHashSet(StringComparer.Ordinal);
        scopes.Add(Scopes.OpenId);
        scopes.Add(Scopes.Email);
        scopes.Add(Scopes.Profile);
        scopes.Add(Scopes.OfflineAccess);

        identity.SetScopes(scopes);
        identity.SetResources("english-learning-api");

        foreach (var claim in identity.Claims)
        {
            claim.SetDestinations(GetDestinations(claim));
        }

        return new ClaimsPrincipal(identity);
    }

    private async Task CreateUserSessionAndRefreshFamilyAsync(User user, ClaimsPrincipal principal)
    {
        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            DeviceIdHash = ComputeHash(HttpContext.Request.Headers.UserAgent.ToString() + HttpContext.Connection.RemoteIpAddress),
            UserAgentSummary = HttpContext.Request.Headers.UserAgent.ToString(),
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            RiskLevel = "Low",
            CreatedAt = DateTimeOffset.UtcNow,
            LastSeenAt = DateTimeOffset.UtcNow
        };

        string initialHash = ComputeHash(Guid.NewGuid().ToString("N"));
        var family = new RefreshTokenFamily
        {
            Id = Guid.NewGuid(),
            SessionId = session.Id,
            UserId = user.Id,
            TokenHash = initialHash,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
            CreatedAt = DateTimeOffset.UtcNow
        };

        var identity = (ClaimsIdentity)principal.Identity!;
        var rtFamilyClaim = new Claim("rt_family_id", family.Id.ToString());
        rtFamilyClaim.SetDestinations(Destinations.AccessToken);
        identity.AddClaim(rtFamilyClaim);

        var rtHashClaim = new Claim("rt_token_hash", initialHash);
        rtHashClaim.SetDestinations(Destinations.AccessToken);
        identity.AddClaim(rtHashClaim);

        var sidClaim = new Claim("sid", session.Id.ToString());
        sidClaim.SetDestinations(Destinations.AccessToken);
        identity.AddClaim(sidClaim);

        await _dbContext.Sessions.AddAsync(session);
        await _dbContext.RefreshTokenFamilies.AddAsync(family);
        await _dbContext.SaveChangesAsync();
    }

    private static IEnumerable<string> GetDestinations(Claim claim) => claim.Type switch
    {
        Claims.Name or Claims.Email or Claims.Role => [Destinations.AccessToken, Destinations.IdentityToken],
        "rt_family_id" or "sid" => [Destinations.AccessToken],
        _ => [Destinations.AccessToken]
    };

    private static string ComputeHash(string input)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
