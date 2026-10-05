using Auth.Application.Interfaces;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace Auth.Infrastructure.Email;

public class MailpitEmailSender : IEmailSenderService
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _fromAddress;
    private readonly ILogger<MailpitEmailSender> _logger;

    public MailpitEmailSender(IConfiguration configuration, ILogger<MailpitEmailSender> logger)
    {
        _host = configuration["SMTP_HOST"] ?? "localhost";
        _port = int.TryParse(configuration["SMTP_PORT"], out int p) ? p : 1025;
        _fromAddress = configuration["SMTP_FROM"] ?? "noreply@englishlearning.local";
        _logger = logger;
    }

    public async Task SendEmailVerificationAsync(string toEmail, string verificationToken, CancellationToken cancellationToken = default)
    {
        string subject = "Verify your English Learning account";
        string body = $"""
            <h1>Welcome to English Learning System!</h1>
            <p>Please verify your email address by submitting this token:</p>
            <p style="font-size: 18px; font-weight: bold; background: #eee; padding: 10px; display: inline-block;">
                {verificationToken}
            </p>
            <p>Or use the verification link in the app.</p>
            """;

        await SendEmailInternalAsync(toEmail, subject, body, cancellationToken);
    }

    public async Task SendPasswordResetAsync(string toEmail, string resetToken, CancellationToken cancellationToken = default)
    {
        string subject = "Reset your English Learning password";
        string body = $"""
            <h1>Password Reset Request</h1>
            <p>You requested a password reset. Use the token below to reset your password:</p>
            <p style="font-size: 18px; font-weight: bold; background: #eee; padding: 10px; display: inline-block;">
                {resetToken}
            </p>
            <p>If you did not request this, please ignore this email.</p>
            """;

        await SendEmailInternalAsync(toEmail, subject, body, cancellationToken);
    }

    public async Task SendSecurityAlertAsync(string toEmail, string subject, string alertMessage, CancellationToken cancellationToken = default)
    {
        string body = $"""
            <h2>Security Alert for your account</h2>
            <p>{alertMessage}</p>
            <p>If this was not you, please log in immediately and revoke active sessions.</p>
            """;

        await SendEmailInternalAsync(toEmail, subject, body, cancellationToken);
    }

    private async Task SendEmailInternalAsync(string toEmail, string subject, string htmlBody, CancellationToken cancellationToken)
    {
        try
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("English Learning Platform", _fromAddress));
            message.To.Add(new MailboxAddress("", toEmail));
            message.Subject = subject;

            var bodyBuilder = new BodyBuilder { HtmlBody = htmlBody };
            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(_host, _port, false, cancellationToken);
            await client.SendAsync(message, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);

            _logger.LogInformation("Sent email '{Subject}' to {ToEmail}", subject, toEmail);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email '{Subject}' to {ToEmail} via {Host}:{Port}", subject, toEmail, _host, _port);
            throw;
        }
    }
}
