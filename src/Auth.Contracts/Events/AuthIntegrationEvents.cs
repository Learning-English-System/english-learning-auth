using BuildingBlocks.Messaging.Contracts;

namespace Auth.Contracts.Events;

public record UserRegisteredIntegrationEvent(
    Guid UserId,
    string Email,
    string? DisplayName
) : IIntegrationEvent
{
    public string EventType => "auth.user.registered.v1";
    public int EventVersion => 1;
}

public record UserEmailVerifiedIntegrationEvent(
    Guid UserId,
    string Email
) : IIntegrationEvent
{
    public string EventType => "auth.user.email-verified.v1";
    public int EventVersion => 1;
}

public record UserDisabledIntegrationEvent(
    Guid UserId,
    string Reason
) : IIntegrationEvent
{
    public string EventType => "auth.user.disabled.v1";
    public int EventVersion => 1;
}
