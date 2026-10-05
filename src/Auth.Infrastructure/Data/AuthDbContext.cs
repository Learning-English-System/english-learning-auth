using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using BuildingBlocks.Messaging.Outbox;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Data;

public class AuthDbContext : IdentityDbContext<User, Role, Guid>, IAuthDbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    public DbSet<UserSession> Sessions => Set<UserSession>();
    public DbSet<RefreshTokenFamily> RefreshTokenFamilies => Set<RefreshTokenFamily>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<OutboxMessage> OutboxMessages => Set<OutboxMessage>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure OpenIddict tables
        builder.UseOpenIddict();

        // User
        builder.Entity<User>(entity =>
        {
            entity.ToTable("Users");
            entity.Property(u => u.Status).HasConversion<int>();
            entity.HasMany(u => u.Sessions).WithOne(s => s.User).HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
            entity.HasMany(u => u.RefreshTokenFamilies).WithOne(r => r.User).HasForeignKey(r => r.UserId).OnDelete(DeleteBehavior.NoAction);
            entity.HasMany(u => u.SecurityEvents).WithOne(e => e.User).HasForeignKey(e => e.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        // UserSession
        builder.Entity<UserSession>(entity =>
        {
            entity.ToTable("UserSessions");
            entity.HasKey(s => s.Id);
            entity.Property(s => s.DeviceIdHash).HasMaxLength(128).IsRequired();
            entity.Property(s => s.IpAddress).HasMaxLength(64);
            entity.Property(s => s.GeoCountry).HasMaxLength(64);
            entity.Property(s => s.GeoRegion).HasMaxLength(64);
            entity.Property(s => s.GeoCity).HasMaxLength(64);
            entity.Property(s => s.RiskLevel).HasMaxLength(32).IsRequired();
            entity.HasIndex(s => s.UserId);
            entity.HasIndex(s => new { s.UserId, s.DeviceIdHash });
        });

        // RefreshTokenFamily
        builder.Entity<RefreshTokenFamily>(entity =>
        {
            entity.ToTable("RefreshTokenFamilies");
            entity.HasKey(f => f.Id);
            entity.Property(f => f.TokenHash).HasMaxLength(128).IsRequired();
            entity.Property(f => f.PreviousTokenHash).HasMaxLength(128);
            entity.HasIndex(f => f.UserId);
            entity.HasIndex(f => f.TokenHash);
            entity.HasIndex(f => f.SessionId);
        });

        // SecurityEvent
        builder.Entity<SecurityEvent>(entity =>
        {
            entity.ToTable("SecurityEvents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.EventType).HasMaxLength(64).IsRequired();
            entity.Property(e => e.IpAddress).HasMaxLength(64);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.CreatedAt);
        });

        // OutboxMessage
        builder.Entity<OutboxMessage>(entity =>
        {
            entity.ToTable("OutboxMessages");
            entity.HasKey(o => o.Id);
            entity.Property(o => o.EventType).HasMaxLength(128).IsRequired();
            entity.Property(o => o.PartitionKey).HasMaxLength(128).IsRequired();
            entity.Property(o => o.PayloadJson).IsRequired();
            entity.HasIndex(o => new { o.PublishedAtUtc, o.CreatedAtUtc });
        });
    }
}
