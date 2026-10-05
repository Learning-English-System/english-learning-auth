using Auth.Contracts.DTOs;

namespace Auth.Application.Services;

public interface IAuthService
{
    Task<RegisterResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);
    Task<bool> VerifyEmailAsync(VerifyEmailRequest request, CancellationToken cancellationToken = default);
    Task ResendVerificationEmailAsync(ResendVerificationRequest request, CancellationToken cancellationToken = default);
    Task ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default);
    Task<bool> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default);
    Task<GoogleLoginResponse> GoogleLoginAsync(GoogleLoginRequest request, string ipAddress, string userAgent, CancellationToken cancellationToken = default);
}
