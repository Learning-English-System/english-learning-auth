namespace Auth.Application.Interfaces;

public interface IEmailSenderService
{
    Task SendEmailVerificationAsync(string toEmail, string verificationToken, CancellationToken cancellationToken = default);
    Task SendPasswordResetAsync(string toEmail, string resetToken, CancellationToken cancellationToken = default);
    Task SendSecurityAlertAsync(string toEmail, string subject, string alertMessage, CancellationToken cancellationToken = default);
}
