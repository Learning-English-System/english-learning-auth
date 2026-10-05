namespace Auth.Domain.Entities;

public class UserSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string DeviceIdHash { get; set; } = string.Empty;
    public string? UserAgentSummary { get; set; }
    public string? IpAddress { get; set; }
    public string? GeoCountry { get; set; }
    public string? GeoRegion { get; set; }
    public string? GeoCity { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string RiskLevel { get; set; } = "Low";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevocationReason { get; set; }

    public bool IsActive => RevokedAt == null;

    public User? User { get; set; }
}
