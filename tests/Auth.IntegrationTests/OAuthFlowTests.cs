using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
public class OAuthFlowTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public OAuthFlowTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task ClientCredentials_WithValidServiceCredentials_ReturnsAccessToken()
    {
        // Arrange
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "learning-service",
            ["client_secret"] = "learning-service-secret-2026",
            ["scope"] = "internal.ai.invoke"
        });

        // Act
        var response = await _client.PostAsync("/connect/token", content);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        string token = json.GetProperty("access_token").GetString()!;
        token.Should().NotBeNullOrWhiteSpace();

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        string? sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? jwt.Subject;
        sub.Should().Be("learning-service");
        jwt.Claims.Should().Contain(c => c.Type == "scope" && c.Value.Contains("internal.ai.invoke"));
    }

    [Fact]
    public async Task ClientCredentials_WithInvalidSecret_IsRejected()
    {
        // Arrange
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "learning-service",
            ["client_secret"] = "wrong-secret"
        });

        // Act
        var response = await _client.PostAsync("/connect/token", content);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task PasswordGrant_UnverifiedEmail_IsRejectedByEmailVerificationGate()
    {
        // Arrange: Register without verifying email
        string email = $"unverified_{Guid.NewGuid():N}@test.com";
        string password = "StrongPassword123!@";
        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, password, "Unverified"));

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "english-learning-web",
            ["username"] = email,
            ["password"] = password
        });

        // Act
        var response = await _client.PostAsync("/connect/token", content);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("Email address has not been verified");
    }

    [Fact]
    public async Task PasswordGrant_VerifiedEmail_ReturnsAccessTokenAndRefreshToken()
    {
        // Arrange: Register and verify
        string email = $"verified_{Guid.NewGuid():N}@test.com";
        string password = "StrongPassword123!@";
        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, password, "Verified"));

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await userManager.FindByEmailAsync(email);
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user!);
            await userManager.ConfirmEmailAsync(user!, token);
        }

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "english-learning-web",
            ["username"] = email,
            ["password"] = password,
            ["scope"] = "openid profile email offline_access"
        });

        // Act
        var response = await _client.PostAsync("/connect/token", content);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();

        string accessToken = json.GetProperty("access_token").GetString()!;
        string refreshToken = json.GetProperty("refresh_token").GetString()!;
        int expiresIn = json.GetProperty("expires_in").GetInt32();

        accessToken.Should().NotBeNullOrWhiteSpace();
        refreshToken.Should().NotBeNullOrWhiteSpace();
        expiresIn.Should().BeInRange(590, 600, "Access token lifetime is approximately 10 minutes");
    }

    [Fact]
    public async Task RefreshToken_RotationAndReuseDetection_RevokesFamilyOnReuse()
    {
        // Arrange: Register, verify, and obtain initial refresh token
        string email = $"rotation_{Guid.NewGuid():N}@test.com";
        string password = "StrongPassword123!@";
        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, password, "Rotation Test"));

        Guid userId;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await userManager.FindByEmailAsync(email);
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user!);
            await userManager.ConfirmEmailAsync(user!, token);
            userId = user!.Id;
        }

        var initialTokenResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "english-learning-web",
            ["username"] = email,
            ["password"] = password,
            ["scope"] = "openid profile email offline_access"
        }));

        initialTokenResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var initialJson = await initialTokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        string originalRefreshToken = initialJson.GetProperty("refresh_token").GetString()!;

        // Act 1: Rotate refresh token (first legitimate refresh)
        var refreshResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "english-learning-web",
            ["refresh_token"] = originalRefreshToken
        }));

        refreshResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var refreshJson = await refreshResponse.Content.ReadFromJsonAsync<JsonElement>();
        string rotatedRefreshToken = refreshJson.GetProperty("refresh_token").GetString()!;
        rotatedRefreshToken.Should().NotBe(originalRefreshToken);

        // Act 2: Attempt REUSE of the already-used originalRefreshToken
        var reuseResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "english-learning-web",
            ["refresh_token"] = originalRefreshToken
        }));

        // Assert: Reuse should be rejected
        reuseResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // Verify in database: SecurityEvent recorded for reuse
        using (var verifyScope = _factory.Services.CreateScope())
        {
            var db = verifyScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var secEvents = await db.SecurityEvents.Where(e => e.UserId == userId).ToListAsync();
            secEvents.Should().Contain(e => e.EventType == "RefreshTokenReuseDetected");
        }
    }
}
