using Auth.Application.Interfaces;
using Auth.Contracts.DTOs;
using Auth.Domain.Entities;
using BuildingBlocks.Web.Exceptions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Application.Services;

public interface ISessionService
{
    Task<IReadOnlyList<SessionDto>> GetActiveSessionsAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken = default);
    Task RevokeSessionAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken = default);
    Task LogoutCurrentSessionAsync(Guid userId, Guid? sessionId, CancellationToken cancellationToken = default);
    Task LogoutAllSessionsAsync(Guid userId, CancellationToken cancellationToken = default);
}

public class SessionService : ISessionService
{
    private readonly IAuthDbContext _dbContext;
    private readonly UserManager<User> _userManager;

    public SessionService(IAuthDbContext dbContext, UserManager<User> userManager)
    {
        _dbContext = dbContext;
        _userManager = userManager;
    }

    public async Task<IReadOnlyList<SessionDto>> GetActiveSessionsAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken = default)
    {
        var sessions = await _dbContext.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .OrderByDescending(s => s.LastSeenAt)
            .ToListAsync(cancellationToken);

        return sessions.Select(s => new SessionDto(
            Id: s.Id,
            DeviceSummary: s.UserAgentSummary,
            IpAddress: s.IpAddress,
            Location: $"{s.GeoCountry} {s.GeoCity}".Trim(),
            CreatedAt: s.CreatedAt,
            LastSeenAt: s.LastSeenAt,
            IsCurrent: currentSessionId.HasValue && s.Id == currentSessionId.Value
        )).ToList();
    }

    public async Task RevokeSessionAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        var session = await _dbContext.Sessions
            .FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);

        if (session == null)
        {
            throw new NotFoundException("Session", sessionId);
        }

        if (session.UserId != userId)
        {
            throw new ForbiddenException("Cannot revoke a session that does not belong to you.");
        }

        session.RevokedAt = DateTimeOffset.UtcNow;
        session.RevocationReason = "UserRevoked";

        // Revoke all refresh token families for this session
        var families = await _dbContext.RefreshTokenFamilies
            .Where(f => f.SessionId == sessionId && f.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var f in families)
        {
            f.RevokedAt = DateTimeOffset.UtcNow;
            f.RevocationReason = "SessionRevoked";
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task LogoutCurrentSessionAsync(Guid userId, Guid? sessionId, CancellationToken cancellationToken = default)
    {
        if (sessionId.HasValue)
        {
            await RevokeSessionAsync(userId, sessionId.Value, cancellationToken);
        }
        else
        {
            // Revoke most recent active session
            var latest = await _dbContext.Sessions
                .Where(s => s.UserId == userId && s.RevokedAt == null)
                .OrderByDescending(s => s.LastSeenAt)
                .FirstOrDefaultAsync(cancellationToken);

            if (latest != null)
            {
                await RevokeSessionAsync(userId, latest.Id, cancellationToken);
            }
        }
    }

    public async Task LogoutAllSessionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user != null)
        {
            user.LastSecurityChangeAt = DateTimeOffset.UtcNow;
            await _userManager.UpdateSecurityStampAsync(user);
        }

        var activeSessions = await _dbContext.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var s in activeSessions)
        {
            s.RevokedAt = DateTimeOffset.UtcNow;
            s.RevocationReason = "LogoutAll";
        }

        var activeFamilies = await _dbContext.RefreshTokenFamilies
            .Where(f => f.UserId == userId && f.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var f in activeFamilies)
        {
            f.RevokedAt = DateTimeOffset.UtcNow;
            f.RevocationReason = "LogoutAll";
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }
}
