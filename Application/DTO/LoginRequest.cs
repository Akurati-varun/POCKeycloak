using System.Text.Json.Serialization;

namespace POCKeycloak.Application.DTO
{
    public class LoginRequest
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty;

        [JsonPropertyName("returnUrl")]
        public string? ReturnUrl { get; set; }
    }
}