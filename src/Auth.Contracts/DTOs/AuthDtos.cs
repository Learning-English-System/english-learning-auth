using System.ComponentModel.DataAnnotations;

namespace Auth.Contracts.DTOs;

public record RegisterRequest(
    [Required, EmailAddress] string Email,
    [Required, MinLength(12, ErrorMessage = "Password must be at least 12 characters.")] string Password,
    [MaxLength(100)] string? DisplayName
);

public record RegisterResponse(
    Guid UserId,
    string Email,
    bool RequiresEmailVerification
);

public record VerifyEmailRequest(
    [Required, EmailAddress] string Email,
    [Required] string Token
);

public record ResendVerificationRequest(
    [Required, EmailAddress] string Email
);

public record ForgotPasswordRequest(
    [Required, EmailAddress] string Email
);

public record ResetPasswordRequest(
    [Required, EmailAddress] string Email,
    [Required] string Token,
    [Required, MinLength(12, ErrorMessage = "Password must be at least 12 characters.")] string NewPassword
);

public record SessionDto(
    Guid Id,
    string? DeviceSummary,
    string? IpAddress,
    string? Location,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastSeenAt,
    bool IsCurrent
);

public record GoogleLoginRequest(
    [Required] string IdToken,
    [EmailAddress] string? Email,
    string? DisplayName,
    LocationPayload? Location
);

public record GoogleLoginResponse(
    Guid UserId,
    string Email,
    string DisplayName,
    bool IsNewUser
);
