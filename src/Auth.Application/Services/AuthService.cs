using Auth.Application.Interfaces;
using Auth.Contracts.DTOs;
using Auth.Contracts.Events;
using Auth.Domain.Entities;
using BuildingBlocks.Messaging.Contracts;
using BuildingBlocks.Messaging.Outbox;
using BuildingBlocks.Security.Constants;
using BuildingBlocks.Web.Correlation;
using BuildingBlocks.Web.Exceptions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<Role> _roleManager;
    private readonly IAuthDbContext _dbContext;
    private readonly IEmailSenderService _emailSender;
    private readonly ICorrelationIdContext _correlationIdContext;
    private readonly IRiskEngineService _riskEngine;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        UserManager<User> userManager,
        RoleManager<Role> roleManager,
        IAuthDbContext dbContext,
        IEmailSenderService emailSender,
        ICorrelationIdContext correlationIdContext,
        IRiskEngineService riskEngine,
        ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _dbContext = dbContext;
        _emailSender = emailSender;
        _correlationIdContext = correlationIdContext;
        _riskEngine = riskEngine;
        _logger = logger;
    }

    public async Task<RegisterResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        string normalizedEmail = request.Email.Trim().ToLowerInvariant();

        var existingUser = await _userManager.FindByEmailAsync(normalizedEmail);
        if (existingUser != null)
        {
            _logger.LogWarning("Registration attempted for existing email {Email}", normalizedEmail);
            throw new ConflictException("An account with this email address already exists.");
        }

        // Validate password minimum length
        if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 12)
        {
            throw new ValidationException("Password must be at least 12 characters long.");
        }

        // Ensure Learner role exists
        if (!await _roleManager.RoleExistsAsync(SecurityConstants.Roles.Learner))
        {
            await _roleManager.CreateAsync(new Role(SecurityConstants.Roles.Learner));
        }

        var user = new User
        {
            UserName = normalizedEmail,
            Email = normalizedEmail,
            Status = UserStatus.PendingVerification,
            CreatedAt = DateTimeOffset.UtcNow,
            LastSecurityChangeAt = DateTimeOffset.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            var errors = result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());
            throw new ValidationException(errors);
        }

        await _userManager.AddToRoleAsync(user, SecurityConstants.Roles.Learner);

        // Generate email verification token
        var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        // Create Outbox message for profile creation
        var registeredEvent = new UserRegisteredIntegrationEvent(user.Id, user.Email, request.DisplayName);
        var envelope = IntegrationEventEnvelope<UserRegisteredIntegrationEvent>.Create(
            registeredEvent.EventType,
            registeredEvent.EventVersion,
            producer: "auth-service",
            correlationId: _correlationIdContext.CorrelationId,
            payload: registeredEvent);

        var outboxMessage = OutboxMessage.FromEnvelope(user.Id.ToString(), envelope);
        await _dbContext.OutboxMessages.AddAsync(outboxMessage, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);

        // Send verification email via adapter
        try
        {
            await _emailSender.SendEmailVerificationAsync(user.Email, emailToken, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email verification to {Email}", user.Email);
            // Non-fatal for registration itself, user can resend verification
        }

        return new RegisterResponse(user.Id, user.Email, RequiresEmailVerification: true);
    }

    public async Task<bool> VerifyEmailAsync(VerifyEmailRequest request, CancellationToken cancellationToken = default)
    {
        string normalizedEmail = request.Email.Trim().ToLowerInvariant();
        var user = await _userManager.FindByEmailAsync(normalizedEmail);
        if (user == null)
        {
            throw new NotFoundException("User", normalizedEmail);
        }

        if (user.EmailConfirmed)
        {
            return true;
        }

        var result = await _userManager.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
        {
            throw new ValidationException("Invalid or expired email verification token.");
        }

        user.Status = UserStatus.Active;
        user.LastSecurityChangeAt = DateTimeOffset.UtcNow;
        await _userManager.UpdateAsync(user);

        // Emit email verified event via Outbox
        var verifiedEvent = new UserEmailVerifiedIntegrationEvent(user.Id, user.Email!);
        var envelope = IntegrationEventEnvelope<UserEmailVerifiedIntegrationEvent>.Create(
            verifiedEvent.EventType,
            verifiedEvent.EventVersion,
            producer: "auth-service",
            correlationId: _correlationIdContext.CorrelationId,
            payload: verifiedEvent);

        var outboxMessage = OutboxMessage.FromEnvelope(user.Id.ToString(), envelope);
        await _dbContext.OutboxMessages.AddAsync(outboxMessage, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return true;
    }

    public async Task ResendVerificationEmailAsync(ResendVerificationRequest request, CancellationToken cancellationToken = default)
    {
        string normalizedEmail = request.Email.Trim().ToLowerInvariant();
        var user = await _userManager.FindByEmailAsync(normalizedEmail);
        if (user == null || user.EmailConfirmed)
        {
            // Do not leak existence of user
            return;
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        await _emailSender.SendEmailVerificationAsync(user.Email!, token, cancellationToken);
    }

    public async Task ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default)
    {
        string normalizedEmail = request.Email.Trim().ToLowerInvariant();
        var user = await _userManager.FindByEmailAsync(normalizedEmail);
        if (user == null)
        {
            // Non-enumerating response
            return;
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        await _emailSender.SendPasswordResetAsync(user.Email!, token, cancellationToken);
    }

    public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        string normalizedEmail = request.Email.Trim().ToLowerInvariant();
        var user = await _userManager.FindByEmailAsync(normalizedEmail);
        if (user == null)
        {
            throw new NotFoundException("User", normalizedEmail);
        }

        var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
        if (!result.Succeeded)
        {
            var errors = result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());
            throw new ValidationException(errors);
        }

        // Revoke all active sessions and refresh token families
        user.LastSecurityChangeAt = DateTimeOffset.UtcNow;
        await _userManager.UpdateSecurityStampAsync(user);

        var activeSessions = await _dbContext.Sessions
            .Where(s => s.UserId == user.Id && s.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var session in activeSessions)
        {
            session.RevokedAt = DateTimeOffset.UtcNow;
            session.RevocationReason = "PasswordReset";
        }

        var activeRefreshFamilies = await _dbContext.RefreshTokenFamilies
            .Where(f => f.UserId == user.Id && f.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var family in activeRefreshFamilies)
        {
            family.RevokedAt = DateTimeOffset.UtcNow;
            family.RevocationReason = "PasswordReset";
        }

        await _dbContext.SaveChangesAsync(cancellationToken);

        return true;
    }

    public async Task<GoogleLoginResponse> GoogleLoginAsync(
        GoogleLoginRequest request,
        string ipAddress,
        string userAgent,
        CancellationToken cancellationToken = default)
    {
        string email = (request.Email ?? "google.user@example.com").Trim().ToLowerInvariant();
        string displayName = request.DisplayName ?? email.Split('@')[0];

        var user = await _userManager.FindByEmailAsync(email);
        bool isNewUser = false;

        if (user == null)
        {
            isNewUser = true;

            if (!await _roleManager.RoleExistsAsync(SecurityConstants.Roles.Learner))
            {
                await _roleManager.CreateAsync(new Role(SecurityConstants.Roles.Learner));
            }

            user = new User
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                Status = UserStatus.Active,
                CreatedAt = DateTimeOffset.UtcNow,
                LastSecurityChangeAt = DateTimeOffset.UtcNow
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                var errors = createResult.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());
                throw new ValidationException(errors);
            }

            await _userManager.AddToRoleAsync(user, SecurityConstants.Roles.Learner);

            var registeredEvent = new UserRegisteredIntegrationEvent(user.Id, user.Email, displayName);
            var envelope = IntegrationEventEnvelope<UserRegisteredIntegrationEvent>.Create(
                registeredEvent.EventType,
                registeredEvent.EventVersion,
                producer: "auth-service",
                correlationId: _correlationIdContext.CorrelationId,
                payload: registeredEvent);

            var outboxMessage = OutboxMessage.FromEnvelope(user.Id.ToString(), envelope);
            await _dbContext.OutboxMessages.AddAsync(outboxMessage, cancellationToken);
        }
        else
        {
            if (!user.EmailConfirmed)
            {
                user.EmailConfirmed = true;
                user.Status = UserStatus.Active;
                await _userManager.UpdateAsync(user);
            }
        }

        var existingLogins = await _userManager.GetLoginsAsync(user);
        if (!existingLogins.Any(l => l.LoginProvider == "Google"))
        {
            await _userManager.AddLoginAsync(user, new UserLoginInfo("Google", $"google-sub-{user.Id:N}", "Google"));
        }

        string deviceIdHash = _riskEngine.ComputeDeviceId(userAgent, ipAddress);
        var assessment = await _riskEngine.AssessLoginRiskAsync(user, deviceIdHash, ipAddress, userAgent, request.Location, cancellationToken);

        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            DeviceIdHash = deviceIdHash,
            UserAgentSummary = userAgent,
            IpAddress = ipAddress,
            GeoCountry = assessment.GeoCountry,
            GeoRegion = assessment.GeoRegion,
            GeoCity = assessment.GeoCity,
            Latitude = assessment.CoarseLatitude,
            Longitude = assessment.CoarseLongitude,
            RiskLevel = assessment.RiskLevel,
            CreatedAt = DateTimeOffset.UtcNow,
            LastSeenAt = DateTimeOffset.UtcNow
        };
        await _dbContext.Sessions.AddAsync(session, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return new GoogleLoginResponse(user.Id, user.Email!, displayName, isNewUser);
    }
}
