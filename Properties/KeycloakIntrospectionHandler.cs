using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
namespace POCKeycloak.Properties
{
    public class KeycloakIntrospectionHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<KeycloakIntrospectionHandler> _logger;

        public KeycloakIntrospectionHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock,
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration)
            : base(options, loggerFactory, encoder, clock)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _logger = loggerFactory.CreateLogger<KeycloakIntrospectionHandler>();
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out var headerValue))
                return AuthenticateResult.NoResult();

            var header = headerValue.ToString();
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return AuthenticateResult.NoResult();

            var token = header.Substring("Bearer ".Length).Trim();
            if (string.IsNullOrEmpty(token))
                return AuthenticateResult.NoResult();

            // --- Get from configuration ---
            var introspectionUrl = _configuration["Keycloak:IntrospectionEndpoint"];
            var clientId = _configuration["Keycloak:ClientId"];
            var clientSecret = _configuration["Keycloak:ClientSecret"];

            if (string.IsNullOrWhiteSpace(introspectionUrl) ||
                string.IsNullOrWhiteSpace(clientId) ||
                string.IsNullOrWhiteSpace(clientSecret))
            {
                _logger.LogError("Keycloak settings missing in configuration.");
                return AuthenticateResult.Fail("Keycloak settings not configured.");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["token"] = token,
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret
                });

                var request = new HttpRequestMessage(HttpMethod.Post, introspectionUrl)
                {
                    Content = content
                };
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                    return AuthenticateResult.Fail("Keycloak introspection request failed.");

                var responseBody = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                if (!root.TryGetProperty("active", out var activeEl) || !activeEl.GetBoolean())
                    return AuthenticateResult.Fail("Inactive token.");

                // --- Build Claims ---
                var claims = new List<Claim>();

                if (root.TryGetProperty("sub", out var sub))
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, sub.GetString() ?? ""));

                if (root.TryGetProperty("preferred_username", out var username))
                    claims.Add(new Claim(ClaimTypes.Name, username.GetString() ?? ""));

                if (root.TryGetProperty("email", out var email))
                    claims.Add(new Claim(ClaimTypes.Email, email.GetString() ?? ""));
                if (root.TryGetProperty("sid", out var sid))
                    claims.Add(new Claim(ClaimTypes.Sid, sid.GetString() ?? ""));

                if (root.TryGetProperty("realm_access", out var realmAccess) &&
                    realmAccess.TryGetProperty("roles", out var roles) &&
                    roles.ValueKind == JsonValueKind.Array)
                {
                    foreach (var role in roles.EnumerateArray())
                    {
                        var roleName = role.GetString();
                        if (!string.IsNullOrEmpty(roleName))
                            claims.Add(new Claim(ClaimTypes.Role, roleName));
                    }
                }

                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to introspect Keycloak token.");
                return AuthenticateResult.Fail("Error introspecting token.");
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers["WWW-Authenticate"] = "Bearer error=\"invalid_token\"";
            return base.HandleChallengeAsync(properties);
        }
    }
}