using System.Net;
using System.Net.Http.Json;
using Auth.Contracts.DTOs;
using Auth.Domain.Entities;
using Auth.Infrastructure.Data;
using BuildingBlocks.Security.Constants;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Auth.IntegrationTests;

[Collection("AuthTests")]
public class AuthEndpointsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public AuthEndpointsTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Register_WithValidData_CreatesUserAndOutboxMessage()
    {
        // Arrange
        string email = $"learner_{Guid.NewGuid():N}@test.com";
        var request = new RegisterRequest(
            Email: email,
            Password: "StrongPassword123!@",
            DisplayName: "Test Learner"
        );

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var registerResponse = await response.Content.ReadFromJsonAsync<RegisterResponse>();
        registerResponse.Should().NotBeNull();
        registerResponse!.Email.Should().Be(email);
        registerResponse.RequiresEmailVerification.Should().BeTrue();

        // Verify in Database
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

        var user = await userManager.FindByEmailAsync(email);
        user.Should().NotBeNull();
        user!.Status.Should().Be(UserStatus.PendingVerification);

        var roles = await userManager.GetRolesAsync(user);
        roles.Should().Contain(SecurityConstants.Roles.Learner);

        // Check Outbox
        var outbox = await db.OutboxMessages.FirstOrDefaultAsync(m => m.PartitionKey == user.Id.ToString());
        outbox.Should().NotBeNull();
        outbox!.EventType.Should().Be("auth.user.registered.v1");
        outbox.PayloadJson.Should().Contain(email);
    }

    [Fact]
    public async Task Register_WithShortPassword_Returns400()
    {
        // Arrange
        var request = new RegisterRequest(
            Email: $"short_pass_{Guid.NewGuid():N}@test.com",
            Password: "short",
            DisplayName: "Short Pass"
        );

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_WithDuplicateEmail_Returns409Conflict()
    {
        // Arrange
        string email = $"duplicate_{Guid.NewGuid():N}@test.com";
        var request = new RegisterRequest(
            Email: email,
            Password: "StrongPassword123!@",
            DisplayName: "Duplicate Learner"
        );

        // First registration
        var firstResponse = await _client.PostAsJsonAsync("/api/auth/register", request);
        firstResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Second registration
        var secondResponse = await _client.PostAsJsonAsync("/api/auth/register", request);

        // Assert
        secondResponse.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task VerifyEmail_WithValidToken_ActivatesUser()
    {
        // Arrange
        string email = $"verify_{Guid.NewGuid():N}@test.com";
        var regRequest = new RegisterRequest(email, "StrongPassword123!@", "Verify User");
        await _client.PostAsJsonAsync("/api/auth/register", regRequest);

        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await userManager.FindByEmailAsync(email);
            token = await userManager.GenerateEmailConfirmationTokenAsync(user!);
        }

        // Act
        var verifyResponse = await _client.PostAsJsonAsync("/api/auth/email/verify", new VerifyEmailRequest(email, token));

        // Assert
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        using (var verifyScope = _factory.Services.CreateScope())
        {
            var verifyUserManager = verifyScope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var updatedUser = await verifyUserManager.FindByEmailAsync(email);
            updatedUser!.EmailConfirmed.Should().BeTrue();
            updatedUser.Status.Should().Be(UserStatus.Active);
        }
    }

    [Fact]
    public async Task ResetPassword_WithValidToken_UpdatesPassword()
    {
        // Arrange
        string email = $"reset_{Guid.NewGuid():N}@test.com";
        var regRequest = new RegisterRequest(email, "OldPassword1234!@", "Reset User");
        await _client.PostAsJsonAsync("/api/auth/register", regRequest);

        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await userManager.FindByEmailAsync(email);
            token = await userManager.GeneratePasswordResetTokenAsync(user!);
        }

        // Act
        var resetResponse = await _client.PostAsJsonAsync("/api/auth/password/reset", new ResetPasswordRequest(email, token, "NewPassword12345!@"));

        // Assert
        resetResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        using (var resetScope = _factory.Services.CreateScope())
        {
            var resetUserManager = resetScope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await resetUserManager.FindByEmailAsync(email);
            var passwordCheck = await resetUserManager.CheckPasswordAsync(user!, "NewPassword12345!@");
            passwordCheck.Should().BeTrue();
        }
    }

    [Fact]
    public async Task OutboxPublisher_PublishesPendingRegistrationMessageToKafka()
    {
        // Arrange
        string email = $"outbox_kafka_{Guid.NewGuid():N}@test.com";
        var request = new RegisterRequest(email, "StrongPassword123!@", "Outbox Kafka Learner");

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Trigger worker to publish pending outbox messages to Kafka KRaft (drain batch)
        var worker = _factory.Services.GetRequiredService<BuildingBlocks.Messaging.Outbox.OutboxPublisherWorker>();
        int processed;
        do
        {
            processed = await worker.ProcessPendingMessagesAsync();
        } while (processed > 0);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var user = await userManager.FindByEmailAsync(email);

        var outbox = await db.OutboxMessages.AsNoTracking().FirstOrDefaultAsync(m => m.PartitionKey == user!.Id.ToString());

        // Assert
        outbox.Should().NotBeNull();
        outbox!.PublishedAtUtc.Should().NotBeNull("OutboxPublisherWorker must publish event to Kafka KRaft and mark PublishedAtUtc");
    }
}
