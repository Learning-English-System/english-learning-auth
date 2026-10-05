using Auth.Application.Services;
using Auth.Contracts.DTOs;
using BuildingBlocks.Security.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/auth")]
[EnableRateLimiting("auth-policy")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ISessionService _sessionService;

    public AuthController(IAuthService authService, ISessionService sessionService)
    {
        _authService = authService;
        _sessionService = sessionService;
    }

    [HttpPost("register")]
    [ProducesResponseType<RegisterResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        var response = await _authService.RegisterAsync(request, cancellationToken);
        return Ok(response);
    }

    [HttpPost("email/verify")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request, CancellationToken cancellationToken)
    {
        await _authService.VerifyEmailAsync(request, cancellationToken);
        return Ok(new { message = "Email verified successfully." });
    }

    [HttpPost("email/resend")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationRequest request, CancellationToken cancellationToken)
    {
        await _authService.ResendVerificationEmailAsync(request, cancellationToken);
        return Ok(new { message = "If the email is unverified, a verification email has been sent." });
    }

    [HttpPost("password/forgot")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request, CancellationToken cancellationToken)
    {
        await _authService.ForgotPasswordAsync(request, cancellationToken);
        return Ok(new { message = "If the email exists, a password reset link has been sent." });
    }

    [HttpPost("password/reset")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        await _authService.ResetPasswordAsync(request, cancellationToken);
        return Ok(new { message = "Password reset successfully. All existing sessions have been revoked." });
    }

    [HttpPost("external/google")]
    [ProducesResponseType<GoogleLoginResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request, CancellationToken cancellationToken)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        var userAgent = Request.Headers.UserAgent.ToString();
        var response = await _authService.GoogleLoginAsync(request, ip, userAgent, cancellationToken);
        return Ok(response);
    }

    [HttpGet("sessions")]
    [Authorize]
    [ProducesResponseType<IReadOnlyList<SessionDto>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetSessions(CancellationToken cancellationToken)
    {
        var userId = User.GetRequiredUserId();
        Guid? currentSessionId = GetCurrentSessionId();
        var sessions = await _sessionService.GetActiveSessionsAsync(userId, currentSessionId, cancellationToken);
        return Ok(sessions);
    }

    [HttpDelete("sessions/{id:guid}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RevokeSession([FromRoute] Guid id, CancellationToken cancellationToken)
    {
        var userId = User.GetRequiredUserId();
        await _sessionService.RevokeSessionAsync(userId, id, cancellationToken);
        return Ok(new { message = "Session revoked successfully." });
    }

    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        var userId = User.GetRequiredUserId();
        Guid? currentSessionId = GetCurrentSessionId();
        await _sessionService.LogoutCurrentSessionAsync(userId, currentSessionId, cancellationToken);
        return Ok(new { message = "Logged out successfully." });
    }

    [HttpPost("logout-all")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LogoutAll(CancellationToken cancellationToken)
    {
        var userId = User.GetRequiredUserId();
        await _sessionService.LogoutAllSessionsAsync(userId, cancellationToken);
        return Ok(new { message = "All sessions logged out successfully." });
    }

    private Guid? GetCurrentSessionId()
    {
        var sidClaim = User.FindFirst("sid")?.Value;
        if (!string.IsNullOrEmpty(sidClaim) && Guid.TryParse(sidClaim, out var guid))
        {
            return guid;
        }

        if (Request.Headers.TryGetValue("X-Session-Id", out var headerVal) && Guid.TryParse(headerVal, out var headerGuid))
        {
            return headerGuid;
        }

        return null;
    }
}
