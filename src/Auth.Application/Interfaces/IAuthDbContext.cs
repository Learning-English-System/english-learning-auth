using Auth.Domain.Entities;
using BuildingBlocks.Messaging.Outbox;
using Microsoft.EntityFrameworkCore;

namespace Auth.Application.Interfaces;

public interface IAuthDbContext
{
    DbSet<User> Users { get; }
    DbSet<Role> Roles { get; }
    DbSet<UserSession> Sessions { get; }
    DbSet<RefreshTokenFamily> RefreshTokenFamilies { get; }
    DbSet<SecurityEvent> SecurityEvents { get; }
    DbSet<OutboxMessage> OutboxMessages { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
