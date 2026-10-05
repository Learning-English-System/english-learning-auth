namespace Auth.Domain.Entities;

public class RefreshTokenFamily
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SessionId { get; set; }
    public Guid UserId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public string? PreviousTokenHash { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevocationReason { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public bool IsRevoked => RevokedAt != null;
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;

    public User? User { get; set; }
    public UserSession? Session { get; set; }
}
