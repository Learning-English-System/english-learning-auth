# English Learning - Authentication & Identity Service

Microservice responsible for Identity management, OpenIddict OAuth 2.0 / OpenID Connect token issuance, PKCE authorization, session management, risk-based anomaly detection, and transactional outbox event publishing.

## Features
- **OpenIddict 7.1.0** authorization server (Token, Refresh, Revocation, Introspection endpoints).
- **ASP.NET Core Identity** on dedicated database (`AuthDb`).
- **Risk Engine**: Impossible travel speed check (>500km/h), new device fingerprinting.
- **Session Management**: Remote session revocation, logout-all.
- **Kafka Outbox**: Publishes `auth.user.registered.v1`.

## Local Development
```bash
# Run unit & integration tests
dotnet test AuthService.slnx

# Run service
dotnet run --project src/Auth.Api --urls http://0.0.0.0:5001
```
