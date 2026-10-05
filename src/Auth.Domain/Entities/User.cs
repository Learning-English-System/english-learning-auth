using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entities;

public class User : IdentityUser<Guid>
{
    public UserStatus Status { get; set; } = UserStatus.PendingVerification;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSecurityChangeAt { get; set; } = DateTimeOffset.UtcNow;

    public ICollection<UserSession> Sessions { get; set; } = [];
    public ICollection<RefreshTokenFamily> RefreshTokenFamilies { get; set; } = [];
    public ICollection<SecurityEvent> SecurityEvents { get; set; } = [];
}
