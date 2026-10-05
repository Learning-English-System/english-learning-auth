using System.Security.Cryptography;
using System.Text;
using Auth.Application.Interfaces;
using Auth.Contracts.DTOs;
using Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Services;

public interface IRiskEngineService
{
    string ComputeDeviceId(string userAgent, string ipAddress);
    Task<LoginRiskAssessment> AssessLoginRiskAsync(
        User user,
        string deviceIdHash,
        string ipAddress,
        string userAgent,
        LocationPayload? locationPayload,
        CancellationToken cancellationToken = default);
}

public class RiskEngineService : IRiskEngineService
{
    private readonly IAuthDbContext _dbContext;
    private readonly IEmailSenderService _emailSender;
    private readonly ILogger<RiskEngineService> _logger;

    public RiskEngineService(
        IAuthDbContext dbContext,
        IEmailSenderService emailSender,
        ILogger<RiskEngineService> logger)
    {
        _dbContext = dbContext;
        _emailSender = emailSender;
        _logger = logger;
    }

    public string ComputeDeviceId(string userAgent, string ipAddress)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{userAgent}|{ipAddress}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public async Task<LoginRiskAssessment> AssessLoginRiskAsync(
        User user,
        string deviceIdHash,
        string ipAddress,
        string userAgent,
        LocationPayload? locationPayload,
        CancellationToken cancellationToken = default)
    {
        int score = 0;
        bool isNewDevice = false;
        bool isNewRegion = false;
        bool isImpossibleTravel = false;

        // Extract coarse coordinates if GPS was granted
        double? coarseLat = locationPayload?.Latitude.HasValue == true
            ? Math.Round(locationPayload.Latitude.Value, 1) // ~11km rounding for privacy
            : null;
        double? coarseLon = locationPayload?.Longitude.HasValue == true
            ? Math.Round(locationPayload.Longitude.Value, 1)
            : null;

        // Coarse location metadata (server/geo fallback)
        string? country = coarseLat.HasValue ? "GPS-Observed" : "DefaultRegion";
        string? region = coarseLat.HasValue ? $"Lat:{coarseLat}" : null;
        string? city = coarseLon.HasValue ? $"Lon:{coarseLon}" : null;

        // Check user session history
        var previousSessions = await _dbContext.Sessions
            .Where(s => s.UserId == user.Id)
            .OrderByDescending(s => s.LastSeenAt)
            .Take(20)
            .ToListAsync(cancellationToken);

        if (previousSessions.Count > 0)
        {
            // Signal 1: New Device
            bool deviceSeen = previousSessions.Any(s => s.DeviceIdHash == deviceIdHash);
            if (!deviceSeen)
            {
                isNewDevice = true;
                score += 35;
            }

            // Signal 2: New Region / Country
            if (country != null)
            {
                bool regionSeen = previousSessions.Any(s => s.GeoCountry == country);
                if (!regionSeen)
                {
                    isNewRegion = true;
                    score += 25;
                }
            }

            // Signal 3: Impossible Travel
            var lastSession = previousSessions.First();
            if (lastSession.Latitude.HasValue && lastSession.Longitude.HasValue && coarseLat.HasValue && coarseLon.HasValue)
            {
                double distanceKm = CalculateDistanceKm(
                    lastSession.Latitude.Value, lastSession.Longitude.Value,
                    coarseLat.Value, coarseLon.Value);

                var timeDiff = DateTimeOffset.UtcNow - lastSession.LastSeenAt;
                if (distanceKm > 500 && timeDiff.TotalHours < 1.0)
                {
                    isImpossibleTravel = true;
                    score += 60;
                }
            }
        }

        string riskLevel = score switch
        {
            >= 70 => "High",
            >= 30 => "Medium",
            _ => "Low"
        };

        // Record security audit event
        var secEvent = new SecurityEvent
        {
            UserId = user.Id,
            EventType = isImpossibleTravel ? "ImpossibleTravelAlert" : isNewDevice ? "NewDeviceLogin" : "UserLogin",
            IpAddress = ipAddress,
            GeoLocation = $"{country}/{region}",
            RiskScore = score,
            MetadataJson = $"{{\"riskLevel\":\"{riskLevel}\",\"isNewDevice\":{isNewDevice.ToString().ToLower()},\"isImpossibleTravel\":{isImpossibleTravel.ToString().ToLower()}}}"
        };
        await _dbContext.SecurityEvents.AddAsync(secEvent, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);

        // If medium/high risk, send security alert email
        if (score >= 30)
        {
            try
            {
                string alertDetails = $"Sign-in from {(isNewDevice ? "a new device" : "an unrecognized location")}. Approximate location: {country} {city}. IP: {ipAddress}";
                await _emailSender.SendSecurityAlertAsync(
                    user.Email!,
                    $"Security Alert: New Sign-in ({riskLevel} Risk)",
                    alertDetails,
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send suspicious login email to {Email}", user.Email);
            }
        }

        return new LoginRiskAssessment(
            RiskLevel: riskLevel,
            RiskScore: score,
            GeoCountry: country,
            GeoRegion: region,
            GeoCity: city,
            CoarseLatitude: coarseLat,
            CoarseLongitude: coarseLon,
            IsNewDevice: isNewDevice,
            IsNewRegion: isNewRegion,
            IsImpossibleTravel: isImpossibleTravel
        );
    }

    private static double CalculateDistanceKm(double lat1, double lon1, double lat2, double lon2)
    {
        const double r = 6371.0; // Earth radius in km
        double dLat = ToRadians(lat2 - lat1);
        double dLon = ToRadians(lon2 - lon1);
        double a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                   Math.Cos(ToRadians(lat1)) * Math.Cos(ToRadians(lat2)) *
                   Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        double c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
        return r * c;
    }

    private static double ToRadians(double degrees) => degrees * Math.PI / 180.0;
}
