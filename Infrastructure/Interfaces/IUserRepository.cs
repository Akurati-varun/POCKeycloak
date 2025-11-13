
namespace POCKeycloak.Infrastructure.Interfaces
{
    public interface IUserRepository
    {
        /// <summary>
        /// Validate credentials against the (for now) in-memory store.
        /// </summary>
        Task<bool> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default);
    }
}