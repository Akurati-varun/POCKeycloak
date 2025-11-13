using Keycloak.AuthServices.Common.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using POCKeycloak.Application.DTO;
using POCKeycloak.Application.Interfaces;
using System.Security.Claims;
using System.Threading.Tasks;

namespace POCKeycloak.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        // POST /auth/login
        // Accepts JSON: { "username": "...", "password": "...", "returnUrl": "..." }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
                return BadRequest(new { error = "username_and_password_required" });

            // Validate credentials against the repository/store first
            var credentialsValid = await _userService.ValidateCredentialsAsync(request.Username, request.Password, HttpContext.RequestAborted);
            if (!credentialsValid)
            {
                return Unauthorized(new { error = "invalid_credentials" });
            }

            // Only attempt to acquire a token when credentials are valid
            var tokenResponse = await _userService.AcquireTokenAsync(request.Username, request.Password, HttpContext.RequestAborted);

            if (tokenResponse is null)
            {
                return Unauthorized(new { error = "invalid_grant_or_credentials" });
            }

            if (!string.IsNullOrEmpty(request.ReturnUrl))
            {
                // Basic redirect with access_token as query parameter (demo only; avoid this in production)
                var separator = request.ReturnUrl.Contains('?') ? '&' : '?';
                var accessToken = tokenResponse?.AccessToken ?? string.Empty;
                var redirectUrl = $"{request.ReturnUrl}{separator}access_token={Uri.EscapeDataString(accessToken)}";
                return Ok(redirectUrl);
            }

            return Ok(tokenResponse);
        }

        // POST /auth/refresh
        // Accepts JSON: { "refreshToken": "..." }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.RefreshToken))
                return BadRequest(new { error = "refresh_token_required" });

            var tokenResponse = await _userService.RefreshTokenAsync(request.RefreshToken, HttpContext.RequestAborted);
            if (tokenResponse is null)
                return Unauthorized(new { error = "invalid_refresh_token" });

            return Ok(tokenResponse);
        }

        // POST /auth/proxy
        // Only accessible by users in the 'organizer' role. Creates a temporary proxy link for a guest.
        [Authorize(Roles = "organizer")]
        [HttpPost("proxy")]
        public async Task<IActionResult> CreateProxyLink([FromBody] ProxyLinkRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.FirstName) || string.IsNullOrWhiteSpace(request.Email))
                return BadRequest(new { error = "firstname_and_email_required" });

            var link = await _userService.CreateProxyLinkAsync(request, HttpContext.RequestAborted);
            return Ok(link);
        }

        // POST /auth/logout
        // Invalidates the access token (and refresh token, if present)
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            // For security, reject logout requests without authentication
            if (!User.Identity?.IsAuthenticated ?? true)
                return Unauthorized(new { error = "unauthorized" });
            var response= await _userService.Logout(User.FindFirst(ClaimTypes.Sid)?.Value ?? string.Empty,HttpContext.RequestAborted);
            // TODO: Invalidate the access token and refresh token (if using) in the backing store
            // This typically involves removing them from the database or marking them as revoked
            if (!response)
            {
                return BadRequest(new { error = "logout_failed" });
            }
            return Ok();
        }

        [Authorize]
        [HttpGet("debug-roles")]
        public IActionResult DebugRoles()
        {
            var roles = User.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList();

            return Ok(new { roles });
        }

        [Authorize(Roles = "admin")]
        [HttpPost("loginas")]
        public async Task<IActionResult> LoginAs([FromBody] LoginAsRequest request)
        {
            if (request is null || string.IsNullOrWhiteSpace(request.UserId))
                return BadRequest(new { error = "user_id_required" });

            var adminUserId = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Sid)?.Value;
            if (string.IsNullOrWhiteSpace(adminUserId))
                return Unauthorized(new { error = "admin_user_id_required" });

            var tokenResponse = await _userService.LoginAsAsync(request.UserId, adminUserId, HttpContext.RequestAborted);
            if (tokenResponse is null)
                return BadRequest(new { error = "impersonation_failed" });

            return Ok(tokenResponse);
        }
    }

}
