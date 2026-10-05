namespace Auth.Contracts.DTOs;

public record LocationPayload(
    double? Latitude,
    double? Longitude,
    double? Accuracy
);

public record LoginRiskAssessment(
    string RiskLevel, // "Low", "Medium", "High"
    int RiskScore,
    string? GeoCountry,
    string? GeoRegion,
    string? GeoCity,
    double? CoarseLatitude,
    double? CoarseLongitude,
    bool IsNewDevice,
    bool IsNewRegion,
    bool IsImpossibleTravel
);
