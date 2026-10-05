using Auth.Application.Interfaces;
using BuildingBlocks.Messaging.Outbox;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Outbox;

public class SqlOutboxRepository : IOutboxRepository
{
    private readonly IAuthDbContext _dbContext;

    public SqlOutboxRepository(IAuthDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task AddAsync(OutboxMessage message, CancellationToken cancellationToken = default)
    {
        await _dbContext.OutboxMessages.AddAsync(message, cancellationToken);
    }

    public async Task<IReadOnlyList<OutboxMessage>> GetPendingAsync(int batchSize, CancellationToken cancellationToken = default)
    {
        return await _dbContext.OutboxMessages
            .Where(m => m.PublishedAtUtc == null && m.RetryCount < 5)
            .OrderBy(m => m.CreatedAtUtc)
            .Take(batchSize)
            .ToListAsync(cancellationToken);
    }

    public async Task MarkPublishedAsync(Guid id, DateTimeOffset publishedAtUtc, CancellationToken cancellationToken = default)
    {
        var message = await _dbContext.OutboxMessages.FirstOrDefaultAsync(m => m.Id == id, cancellationToken);
        if (message != null)
        {
            message.PublishedAtUtc = publishedAtUtc;
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task MarkFailedAsync(Guid id, string error, CancellationToken cancellationToken = default)
    {
        var message = await _dbContext.OutboxMessages.FirstOrDefaultAsync(m => m.Id == id, cancellationToken);
        if (message != null)
        {
            message.RetryCount++;
            message.Error = error;
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
    }
}
