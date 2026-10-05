namespace Auth.Domain.Entities;

public class SecurityEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string EventType { get; set; } = string.Empty;
    public Guid? SessionId { get; set; }
    public string? IpAddress { get; set; }
    public string? GeoLocation { get; set; }
    public string? MetadataJson { get; set; }
    public int RiskScore { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User? User { get; set; }
}
