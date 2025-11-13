using POCKeycloak.Infrastructure.Interfaces;

namespace POCKeycloak.Infrastructure.Repositories
{
    /// <summary>
    /// Simple hardcoded user store for development/demo.
    /// Replace with real DB or identity store later.
    /// </summary>
    public class UserRepository : IUserRepository
    {
        private readonly Dictionary<string, string> _users = new(StringComparer.OrdinalIgnoreCase)
        {
            // username -> password (plain text for demo only)
            ["alice"] = "Password123!",
            ["bob"] = "P@ssw0rd!",
            ["myuser"]= "myuser",
            ["mohitsudan"]="mohitsudan",
               ["akhilemani"] = "akhilemani"
        };

        public Task<bool> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                return Task.FromResult(false);

            var valid = _users.TryGetValue(username, out var stored) && stored == password;
            return Task.FromResult(valid);
        }
    }
}