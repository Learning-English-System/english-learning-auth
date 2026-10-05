using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Application.Interfaces;
using Auth.Application.Services;
using Auth.Contracts.DTOs;
using Auth.Domain.Entities;
using Auth.Infrastructure.Data;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Auth.IntegrationTests;

[Collection("AuthTests")]
public class SessionSecurityTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public SessionSecurityTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task GoogleLogin_NewUser_CreatesUserWithLearnerRoleAndOutboxAndSession()
    {
        // Arrange
        string googleEmail = $"google_{Guid.NewGuid():N}@gmail.com";
        var request = new GoogleLoginRequest(
            IdToken: "mock-google-id-token",
            Email: googleEmail,
            DisplayName: "Google Test Learner",
            Location: new LocationPayload(21.028511, 105.854167, 10.0)
        );

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/external/google", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<GoogleLoginResponse>();
        result.Should().NotBeNull();
        result!.Email.Should().Be(googleEmail);
        result.IsNewUser.Should().BeTrue();

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

        var user = await userManager.FindByEmailAsync(googleEmail);
        user.Should().NotBeNull();
        user!.EmailConfirmed.Should().BeTrue();

        var roles = await userManager.GetRolesAsync(user);
        roles.Should().Contain("Learner");

        // Verify outbox message
        var outbox = await db.OutboxMessages.FirstOrDefaultAsync(o => o.PartitionKey == user.Id.ToString());
        outbox.Should().NotBeNull();
        outbox!.EventType.Should().Be("auth.user.registered.v1");

        // Verify session was recorded with coarse geolocation (rounded to 1 decimal place)
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.UserId == user.Id);
        session.Should().NotBeNull();
        session!.Latitude.Should().BeApproximately(21.0, 0.05);
        session.Longitude.Should().BeApproximately(105.9, 0.05);
    }

    [Fact]
    public async Task GoogleLogin_SubsequentLogin_DoesNotDuplicateUser()
    {
        // Arrange
        string googleEmail = $"google_repeat_{Guid.NewGuid():N}@gmail.com";
        var request = new GoogleLoginRequest(
            IdToken: "mock-google-token",
            Email: googleEmail,
            DisplayName: "Repeat Learner",
            Location: null
        );

        // First login
        var resp1 = await _client.PostAsJsonAsync("/api/auth/external/google", request);
        resp1.StatusCode.Should().Be(HttpStatusCode.OK);
        var res1 = await resp1.Content.ReadFromJsonAsync<GoogleLoginResponse>();
        res1!.IsNewUser.Should().BeTrue();

        // Second login
        var resp2 = await _client.PostAsJsonAsync("/api/auth/external/google", request);
        resp2.StatusCode.Should().Be(HttpStatusCode.OK);
        var res2 = await resp2.Content.ReadFromJsonAsync<GoogleLoginResponse>();
        res2!.IsNewUser.Should().BeFalse();
        res2.UserId.Should().Be(res1.UserId);
    }

    [Fact]
    public async Task SessionManagement_ListAndRevoke_RevokesTargetSessionOnly()
    {
        // Arrange: create verified user and obtain access token
        string email = $"session_test_{Guid.NewGuid():N}@test.com";
        string password = "StrongPassword123!@";
        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, password, "Session User"));

        Guid userId;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await userManager.FindByEmailAsync(email);
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user!);
            await userManager.ConfirmEmailAsync(user!, token);
            userId = user!.Id;
        }

        // Login to get access token and session 1
        var tokenResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "english-learning-web",
            ["username"] = email,
            ["password"] = password,
            ["scope"] = "openid profile email offline_access"
        }));
        var tokenJson = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        string accessToken = tokenJson.GetProperty("access_token").GetString()!;

        // Insert a second session manually for the user
        var secondSessionId = Guid.NewGuid();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await db.Sessions.AddAsync(new UserSession
            {
                Id = secondSessionId,
                UserId = userId,
                DeviceIdHash = "device-2",
                UserAgentSummary = "Firefox on Linux",
                IpAddress = "192.168.1.50",
                GeoCountry = "Vietnam",
                GeoCity = "Da Nang",
                CreatedAt = DateTimeOffset.UtcNow,
                LastSeenAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        using var authedClient = _factory.CreateClient();
        authedClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        // Act 1: Get sessions
        var sessionsResponse = await authedClient.GetAsync("/api/auth/sessions");
        sessionsResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var sessions = await sessionsResponse.Content.ReadFromJsonAsync<List<SessionDto>>();
        sessions.Should().NotBeNull();
        sessions!.Count.Should().BeGreaterOrEqualTo(2);

        // Act 2: Revoke second session
        var revokeResponse = await authedClient.DeleteAsync($"/api/auth/sessions/{secondSessionId}");
        revokeResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Assert: Verify DB status
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var revokedSession = await db.Sessions.FirstOrDefaultAsync(s => s.Id == secondSessionId);
            revokedSession!.RevokedAt.Should().NotBeNull();
            revokedSession.RevocationReason.Should().Be("UserRevoked");

            // First session still active
            var activeSession = await db.Sessions.FirstOrDefaultAsync(s => s.UserId == userId && s.RevokedAt == null);
            activeSession.Should().NotBeNull();
        }
    }

    [Fact]
    public async Task RevokeSession_OtherUsersSession_ReturnsForbidden()
    {
        // Arrange: User A and User B
        string emailA = $"usera_{Guid.NewGuid():N}@test.com";
        string emailB = $"userb_{Guid.NewGuid():N}@test.com";
        string password = "StrongPassword123!@";

        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(emailA, password, "User A"));
        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(emailB, password, "User B"));

        Guid userBId;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var userA = await userManager.FindByEmailAsync(emailA);
            var tokA = await userManager.GenerateEmailConfirmationTokenAsync(userA!);
            await userManager.ConfirmEmailAsync(userA!, tokA);

            var userB = await userManager.FindByEmailAsync(emailB);
            var tokB = await userManager.GenerateEmailConfirmationTokenAsync(userB!);
            await userManager.ConfirmEmailAsync(userB!, tokB);
            userBId = userB!.Id;
        }

        // User A gets access token
        var tokRespA = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "english-learning-web",
            ["username"] = emailA,
            ["password"] = password,
            ["scope"] = "openid profile email"
        }));
        var tokJsonA = await tokRespA.Content.ReadFromJsonAsync<JsonElement>();
        string accessTokenA = tokJsonA.GetProperty("access_token").GetString()!;

        // User B has a session
        var sessionBId = Guid.NewGuid();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await db.Sessions.AddAsync(new UserSession
            {
                Id = sessionBId,
                UserId = userBId,
                DeviceIdHash = "devB",
                UserAgentSummary = "Safari",
                IpAddress = "10.0.0.1",
                CreatedAt = DateTimeOffset.UtcNow,
                LastSeenAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        using var authedClientA = _factory.CreateClient();
        authedClientA.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessTokenA);

        // Act: User A tries to revoke User B's session
        var response = await authedClientA.DeleteAsync($"/api/auth/sessions/{sessionBId}");

        // Assert: Forbidden
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task LogoutAll_RevokesAllSessionsAndFamiliesAndUpdatesSecurityStamp()
    {
        // Arrange
        string email = $"logoutall_{Guid.NewGuid():N}@test.com";
        string password = "StrongPassword123!@";
        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, password, "Logout All User"));

        Guid userId;
        string initialStamp;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await userManager.FindByEmailAsync(email);
            var tok = await userManager.GenerateEmailConfirmationTokenAsync(user!);
            await userManager.ConfirmEmailAsync(user!, tok);
            userId = user!.Id;
            initialStamp = user.SecurityStamp!;
        }

        var tokenResp = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "english-learning-web",
            ["username"] = email,
            ["password"] = password,
            ["scope"] = "openid profile email offline_access"
        }));
        var tokenJson = await tokenResp.Content.ReadFromJsonAsync<JsonElement>();
        string accessToken = tokenJson.GetProperty("access_token").GetString()!;

        using var authedClient = _factory.CreateClient();
        authedClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        // Act
        var logoutResponse = await authedClient.PostAsync("/api/auth/logout-all", null);

        // Assert
        logoutResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

            var activeSessions = await db.Sessions.Where(s => s.UserId == userId && s.RevokedAt == null).ToListAsync();
            activeSessions.Should().BeEmpty();

            var activeFamilies = await db.RefreshTokenFamilies.Where(f => f.UserId == userId && f.RevokedAt == null).ToListAsync();
            activeFamilies.Should().BeEmpty();

            var user = await userManager.FindByIdAsync(userId.ToString());
            user!.SecurityStamp.Should().NotBe(initialStamp, "Security stamp should be bumped on logout-all");
        }
    }

    [Fact]
    public async Task RiskEngine_ImpossibleTravel_DetectsHighRiskAndRecordsSecurityEvent()
    {
        using var scope = _factory.Services.CreateScope();
        var riskEngine = scope.ServiceProvider.GetRequiredService<IRiskEngineService>();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

        // Create a user
        string email = $"risk_{Guid.NewGuid():N}@test.com";
        var user = new User
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            Status = UserStatus.Active,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await userManager.CreateAsync(user, "StrongPassword123!@");

        // First session: Hanoi (21.0285, 105.8542) 15 minutes ago
        var firstSession = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            DeviceIdHash = "hanoi-phone",
            UserAgentSummary = "Mobile Safari",
            IpAddress = "113.160.0.1",
            Latitude = 21.0,
            Longitude = 105.9,
            GeoCity = "Hanoi",
            GeoCountry = "Vietnam",
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-15),
            LastSeenAt = DateTimeOffset.UtcNow.AddMinutes(-15)
        };
        await db.Sessions.AddAsync(firstSession);
        await db.SaveChangesAsync();

        // Second assessment: Tokyo (35.6762, 139.6503) only 15 minutes later (>3500km)
        var assessment = await riskEngine.AssessLoginRiskAsync(
            user,
            deviceIdHash: "tokyo-pc",
            ipAddress: "133.242.0.1",
            userAgent: "Chrome Windows",
            locationPayload: new LocationPayload(35.6762, 139.6503, 10.0)
        );

        // Assert
        assessment.RiskLevel.Should().Be("High");
        assessment.IsImpossibleTravel.Should().BeTrue();

        // Verify SecurityEvent was persisted
        var securityEvent = await db.SecurityEvents
            .FirstOrDefaultAsync(e => e.UserId == user.Id && e.EventType == "ImpossibleTravelAlert");
        securityEvent.Should().NotBeNull();
        securityEvent!.RiskScore.Should().BeGreaterOrEqualTo(70);
    }
}
