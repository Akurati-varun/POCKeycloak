using System.Threading;
using System.Threading.Tasks;
using POCKeycloak.Application.DTO;

namespace POCKeycloak.Application.Interfaces
{
    public interface IUserService
    {
        Task<bool> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default);

        /// <summary>
        /// Acquire a token from the configured identity provider for the given credentials.
        /// Returns null when token acquisition failed.
        /// </summary>
        Task<TokenResponse?> AcquireTokenAsync(string username, string password, CancellationToken cancellationToken = default);

        /// <summary>
        /// Acquire a new token using a refresh token.
        /// Returns null when token acquisition failed.
        /// </summary>
        Task<TokenResponse?> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

        /// <summary>
        /// Create a short-lived proxy link token for a guest user not stored in the DB.
        /// Returns a URL that can be used to access the application as the guest.
        /// </summary>
        Task<ProxyLinkResponse> CreateProxyLinkAsync(ProxyLinkRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// Impersonate the specified user (by user id) and acquire a token for that user.
        /// Returns null when impersonation or token acquisition failed.
        /// </summary>
        Task<TokenResponse?> LoginAsAsync(string userId,string adminUserId, CancellationToken cancellationToken = default);
        /// <summary>
        /// Logout the specified user (by user id) and acquire a token for that user.
        /// </summary>
        Task<bool> Logout(string sessionId,CancellationToken cancellationToken = default);
    }
}