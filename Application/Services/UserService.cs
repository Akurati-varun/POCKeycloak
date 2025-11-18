using Microsoft.AspNetCore.Http;
using POCKeycloak.Application.DTO;
using POCKeycloak.Application.Interfaces;
using POCKeycloak.Infrastructure.Interfaces;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace POCKeycloak.Application.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(IUserRepository userRepository, IHttpClientFactory httpClientFactory, IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));

        }

        public Task<bool> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default)
            => _userRepository.ValidateCredentialsAsync(username, password, cancellationToken);

        public async Task<TokenResponse?> AcquireTokenAsync(string username, string password, CancellationToken cancellationToken = default)
        {
            // Public coordinator method — token creation details are encapsulated in a private helper.
            return await AcquireTokenFromIdentityProviderAsync(username, password, cancellationToken);
        }

        // Public: refresh token flow
        public async Task<TokenResponse?> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return null;

            var authority = _configuration["Keycloak:Authority"];
            var tokenEndpoint = $"{authority.TrimEnd('/')}/protocol/openid-connect/token";
            var clientId = _configuration["Keycloak:ClientId"] ?? "dotnet-api";
            var clientSecret = _configuration["Keycloak:ClientSecret"] ?? string.Empty;

            var form = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "refresh_token"),
                new("client_id", clientId),
                new("refresh_token", refreshToken)
            };

            if (!string.IsNullOrEmpty(clientSecret))
            {
                form.Add(new KeyValuePair<string, string>("client_secret", clientSecret));
            }

            var client = _httpClientFactory.CreateClient();
            using var content = new FormUrlEncodedContent(form);
            var response = await client.PostAsync(tokenEndpoint, content, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return tokenResponse;
        }

        // Create a proxy link using Keycloak Admin API: create a temporary user and obtain a token for them.
        public async Task<ProxyLinkResponse> CreateProxyLinkAsync(ProxyLinkRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            // Configuration
            var authority = _configuration["Keycloak:Authority"];
            // Admin endpoints are under /admin/realms/{realm}
            // Extract base url and realm from authority
            // authority is expected to end with /realms/{realm}
            var authorityUri = new Uri(authority);
            var segments = authorityUri.Segments.Select(s => s.Trim('/')).Where(s => !string.IsNullOrEmpty(s)).ToArray();
            if (segments.Length <2)
                throw new InvalidOperationException("Keycloak:Authority must point to a realm (e.g. https://keycloak/realms/{realm}).");

            var realm = segments.Last();
            var keycloakBase = new Uri(authorityUri, "/").ToString().TrimEnd('/');
            var adminBase = new Uri(new Uri(keycloakBase), $"/admin/realms/{realm}").ToString().TrimEnd('/');

            var adminClientId = _configuration["Keycloak:AdminClientId"] ?? _configuration["Keycloak:ClientId"];
            var adminClientSecret = _configuration["Keycloak:AdminClientSecret"] ?? _configuration["Keycloak:ClientSecret"];
            if (string.IsNullOrEmpty(adminClientId) || string.IsNullOrEmpty(adminClientSecret))
                throw new InvalidOperationException("Admin client credentials are not configured. Set Keycloak:AdminClientId and Keycloak:AdminClientSecret with a client that has 'manage-users' privileges.");

            var adminToken = await GetClientCredentialsTokenAsync(adminClientId, adminClientSecret, authority, cancellationToken);
            if (adminToken is null)
                throw new InvalidOperationException("Unable to obtain admin access token from Keycloak.");

            var http = _httpClientFactory.CreateClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

            // Create the user in Keycloak
            var Username = (request.Email ?? string.Empty).Split('@').FirstOrDefault() ?? Guid.NewGuid().ToString("N");
            var createUser = new
            {
                username = Username,
                firstName = request.FirstName,
                lastName = request.LastName,
                email = request.Email,
                enabled = true,
                 emailVerified = true
            };

            var createResp = await http.PostAsJsonAsync($"{adminBase}/users", createUser, cancellationToken);
            if (!createResp.IsSuccessStatusCode)
            {
                var body = await createResp.Content.ReadAsStringAsync(cancellationToken);
                throw new InvalidOperationException($"Failed to create user in Keycloak: {createResp.StatusCode} - {body}");
            }

            // Location header contains path to created user: /admin/realms/{realm}/users/{id}
            var location = createResp.Headers.Location?.ToString();
            string userId;
            if (!string.IsNullOrEmpty(location))
            {
                userId = location.TrimEnd('/').Split('/').Last();
            }
            else
            {
                // fallback: search user by username
                var searchResp = await http.GetAsync($"{adminBase}/users?username={Uri.EscapeDataString(Username)}", cancellationToken);
                var searchBody = await searchResp.Content.ReadAsStringAsync(cancellationToken);
                var users = JsonSerializer.Deserialize<List<JsonElement>>(searchBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                var user = users?.FirstOrDefault();
                userId = user?.GetProperty("id").GetString() ?? throw new InvalidOperationException("Unable to locate created user id.");
            }
            //  Fetch guest role ID
            //var roleResp = await http.GetAsync($"{adminBase}/roles/guest", cancellationToken);
            //if (!roleResp.IsSuccessStatusCode)
            //{
            //    var body = await roleResp.Content.ReadAsStringAsync(cancellationToken);
            //    throw new InvalidOperationException($"Unable to fetch guest role: {roleResp.StatusCode} - {body}");
            //}
            //var roleBody = await roleResp.Content.ReadAsStringAsync(cancellationToken);
            //var guestRole = JsonSerializer.Deserialize<JsonElement>(roleBody);
            //var guestRoleId = guestRole.GetProperty("id").GetString();

            var guestRoleId = "31d336f7-29be-4952-8419-3136b2eb1f4e";
            // Assign guest role to the user
            var roleAssignResp = await http.PostAsJsonAsync(
                $"{adminBase}/users/{userId}/role-mappings/realm",
                new[]
                {
        new { id = guestRoleId, name = "guest" }
                },
                cancellationToken
            );

            if (!roleAssignResp.IsSuccessStatusCode)
            {
                var body = await roleAssignResp.Content.ReadAsStringAsync(cancellationToken);
                throw new InvalidOperationException($"Failed to assign guest role: {roleAssignResp.StatusCode} - {body}");
            }

            // Set a random password for the user
            var randomPassword = Guid.NewGuid().ToString("N") + "!A";
            var credPayload = new
            {
                type = "password",
                value = randomPassword,
                temporary = false
            };

            var setPassResp = await http.PutAsJsonAsync($"{adminBase}/users/{userId}/reset-password", credPayload, cancellationToken);
            if (!setPassResp.IsSuccessStatusCode)
            {
                var body = await setPassResp.Content.ReadAsStringAsync(cancellationToken);
                throw new InvalidOperationException($"Failed to set password for Keycloak user: {setPassResp.StatusCode} - {body}");
            }

            // Optionally set attributes or role mappings here

            // Acquire token for the newly created user using direct grant
            var tokenResp = await AcquireTokenFromIdentityProviderAsync(Username, randomPassword, cancellationToken);
            if (tokenResp is null)
                throw new InvalidOperationException("Failed to acquire token for proxy user.");

            // Build return link — include access_token as query param (demo only)
            var returnBase = request.ReturnUrl ?? _configuration["Proxy:ReturnUrlBase"];
            ProxyLinkResponse link = new ProxyLinkResponse()
            {
             proxyLink= $"{returnBase}{(returnBase.Contains('?') ? '&' : '?')}access_token={Uri.EscapeDataString(tokenResp.AccessToken ?? string.Empty)}"
            };

            return link;
        }

        private async Task<string?> GetClientCredentialsTokenAsync(string clientId, string clientSecret, string authority, CancellationToken cancellationToken)
        {
            var tokenEndpoint = authority.TrimEnd('/') + "/protocol/openid-connect/token";
            var client = _httpClientFactory.CreateClient();
            var form = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "client_credentials"),
                new("client_id", clientId),
                new("client_secret", clientSecret)
            };

            using var content = new FormUrlEncodedContent(form);
            var resp = await client.PostAsync(tokenEndpoint, content, cancellationToken);
            var body = await resp.Content.ReadAsStringAsync(cancellationToken);
            if (!resp.IsSuccessStatusCode)
                return null;

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("access_token", out var tok))
                return tok.GetString();
            return null;
        }

        // Private: encapsulates the identity provider HTTP call / token creation
        private async Task<TokenResponse?> AcquireTokenFromIdentityProviderAsync(string username, string password, CancellationToken cancellationToken)
        {
            var authority = _configuration["Keycloak:Authority"];
            var tokenEndpoint = $"{authority.TrimEnd('/')}/protocol/openid-connect/token";
            var clientId = _configuration["Keycloak:ClientId"] ?? "dotnet-api";
            var clientSecret = _configuration["Keycloak:ClientSecret"]??"FVk9dnhMbWqrllVnkMPukLOdPCajC3pI"; 

            var form = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "password"),
                new("client_id", clientId),
                new("username", username),
                new("password", password),
                new("scope", "openid")
            };

            if (!string.IsNullOrEmpty(clientSecret))
            {
                form.Add(new KeyValuePair<string, string>("client_secret", clientSecret));
            }

            var client = _httpClientFactory.CreateClient();
            using var content = new FormUrlEncodedContent(form);
            var response = await client.PostAsync(tokenEndpoint, content, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                // For now return null on failure. Controller will handle Unauthorized.
                return null;
            }

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return tokenResponse;
        }

        /// <summary>
        /// Impersonate the specified user (by userId) and acquire a token for that user.
        /// After successful impersonation, attempts to invalidate the admin's sessions in Keycloak (best-effort).
        /// Returns a TokenResponse for the target user, or null on failure.
        /// </summary>
        public async Task<TokenResponse?> LoginAsAsync(string userId, string sessionId, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return null;

            var authority = _configuration["Keycloak:Authority"];
            var authorityUri = new Uri(authority);
            var segments = authorityUri.Segments.Select(s => s.Trim('/')).Where(s => !string.IsNullOrEmpty(s)).ToArray();
            if (segments.Length < 2)
                throw new InvalidOperationException("Keycloak:Authority must point to a realm (e.g. https://keycloak/realms/{realm}).");

            var realm = segments.Last();
            var keycloakBase = new Uri(authorityUri, "/").ToString().TrimEnd('/');
            var adminBase = new Uri(new Uri(keycloakBase), $"/admin/realms/{realm}").ToString().TrimEnd('/');

            var adminClientId = _configuration["Keycloak:AdminClientId"] ?? _configuration["Keycloak:ClientId"];
            var adminClientSecret = _configuration["Keycloak:AdminClientSecret"] ?? _configuration["Keycloak:ClientSecret"];
            if (string.IsNullOrEmpty(adminClientId) || string.IsNullOrEmpty(adminClientSecret))
                throw new InvalidOperationException("Admin client credentials are not configured. Set Keycloak:AdminClientId and Keycloak:AdminClientSecret with a client that has 'manage-users' privileges.");

            // Get admin client token (client credentials)
            var adminClientToken = await GetClientCredentialsTokenAsync(adminClientId, adminClientSecret, authority, cancellationToken);
            if (string.IsNullOrEmpty(adminClientToken))
                return null;

            // Try to read the caller's access token (admin bearer token) from current request
            var callerAccessToken = GetBearerTokenFromHttpContext();

            // Prefer using the caller token for token-exchange; fallback to admin client token if caller token not present.
            var subjectToken = !string.IsNullOrEmpty(callerAccessToken) ? callerAccessToken! : adminClientToken;

            // Try token-exchange to obtain a token for requested user
            var tokenResponse = await AcquireTokenViaTokenExchangeAsync(subjectToken, userId, authority, adminClientId, adminClientSecret, cancellationToken);
            if (tokenResponse is null)
                return null;

            // Best-effort: invalidate the admin's sessions so only the impersonated user remains active.
            try
            {
                //var adminUserId = GetCurrentUserIdFromClaims();
                if (!string.IsNullOrEmpty(sessionId))
                {
                    // Use admin client token to call Admin API logout endpoint.
                    var logoutSucceeded = await LogoutAdminSessionAsync(sessionId, adminClientToken, adminBase, cancellationToken);

                    //if (!logoutSucceeded)
                    //{
                    //    // Fallback: try token revocation if logout failed.
                    //    await RevokeTokenAsync(subjectToken, authority, adminClientId, adminClientSecret, cancellationToken);
                    //}
                }
            }
            catch
            {
                // swallow errors — logout is best-effort
            }

            return tokenResponse;
        }

        public async Task<bool> Logout(string sessionId, CancellationToken cancellationToken = default)
        {
            var authority = _configuration["Keycloak:Authority"] ;
            var authorityUri = new Uri(authority);
            var segments = authorityUri.Segments.Select(s => s.Trim('/')).Where(s => !string.IsNullOrEmpty(s)).ToArray();
            if (segments.Length < 2)
                throw new InvalidOperationException("Keycloak:Authority must point to a realm (e.g. https://keycloak/realms/{realm}).");

            var realm = segments.Last();
            var keycloakBase = new Uri(authorityUri, "/").ToString().TrimEnd('/');
            var adminBase = new Uri(new Uri(keycloakBase), $"/admin/realms/{realm}").ToString().TrimEnd('/');

            var adminClientId = _configuration["Keycloak:AdminClientId"] ?? _configuration["Keycloak:ClientId"];
            var adminClientSecret = _configuration["Keycloak:AdminClientSecret"] ?? _configuration["Keycloak:ClientSecret"];
            // Get admin client token (client credentials)
            var adminClientToken = await GetClientCredentialsTokenAsync(adminClientId, adminClientSecret, authority, cancellationToken);
            if (string.IsNullOrEmpty(adminClientToken))
                return false;
            var logoutSucceeded = await LogoutAdminSessionAsync(sessionId, adminClientToken, adminBase, cancellationToken);
            if (!logoutSucceeded)
            {
                // Fallback: try token revocation if logout failed.
                return false;
            }
            return true;
        }

        private string? GetBearerTokenFromHttpContext()
        {
            try
            {
                var ctx = _httpContextAccessor.HttpContext;
                if (ctx == null) return null;
                if (ctx.Request.Headers.TryGetValue("Authorization", out var values))
                {
                    var header = values.FirstOrDefault();
                    if (!string.IsNullOrEmpty(header) && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        return header.Substring("Bearer ".Length).Trim();
                    }
                }
            }
            catch
            {
                // ignore
            }
            return null;
        }

        private async Task<bool> RevokeTokenAsync(
    string tokenToRevoke,
    string authority,
    string clientId,
    string clientSecret,
    CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(tokenToRevoke))
                return false;

            var revokeEndpoint = $"{authority.TrimEnd('/')}/protocol/openid-connect/revoke";

            var form = new List<KeyValuePair<string, string>>
    {
        // The token you want to invalidate (the original subject_token)
        new("token", tokenToRevoke),
        
        // OAuth 2.0 Token Revocation specification mandates client credentials in body
        new("client_id", clientId),
    };

            if (!string.IsNullOrEmpty(clientSecret))
            {
                form.Add(new KeyValuePair<string, string>("client_secret", clientSecret));
            }

            var client = _httpClientFactory.CreateClient();
            using var content = new FormUrlEncodedContent(form);

            // Keycloak typically responds with HTTP 200 OK for successful revocation, 
            // and the body is often empty or status-neutral.
            var response = await client.PostAsync(revokeEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                // **Critical:** Log the response body if revocation fails for diagnosis
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                // _logger.LogWarning("Token Revocation failed: {Body}", body);
            }

            return response.IsSuccessStatusCode;
        }

        private async Task<bool> LogoutAdminSessionAsync(string sessionId, string adminToken, string adminBase, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(adminToken)) return false;

            try
            {
                var http = _httpClientFactory.CreateClient();
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

                // Keycloak Admin API: DELETE /admin/realms/{realm}/sessions/{session}
                var resp = await http.DeleteAsync($"{adminBase}/sessions/{Uri.EscapeDataString(sessionId)}", cancellationToken);

                // Consider 204 NoContent or 200 OK as success depending on Keycloak version
                return resp.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
        

        private async Task<TokenResponse?> AcquireTokenViaTokenExchangeAsync(string subjectToken, string requestedSubjectUserId, string authority, string clientId, string clientSecret, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subjectToken))
                return null;

            var tokenEndpoint = $"{authority.TrimEnd('/')}/protocol/openid-connect/token";

            var form = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                new("subject_token", subjectToken),
                new("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
                 //Keycloak supports requested_subject to ask for tokens for a different user(subject)
                new("requested_subject", requestedSubjectUserId),
                new("client_id", clientId)
            };

            if (!string.IsNullOrEmpty(clientSecret))
            {
                form.Add(new KeyValuePair<string, string>("client_secret", clientSecret));
            }

            var client = _httpClientFactory.CreateClient();
            using var content = new FormUrlEncodedContent(form);
            var response = await client.PostAsync(tokenEndpoint, content, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return tokenResponse;
        }
        
    }
}