using System.Text.Json.Serialization;

namespace POCKeycloak.Application.DTO
{
    public class LoginAsRequest
    {
        [JsonPropertyName("userId")]
        public string UserId { get; set; } = string.Empty;

        // Optional return URL that will receive the token as a query parameter (similar to Login/Proxy)
        [JsonPropertyName("returnUrl")]
        public string? ReturnUrl { get; set; }
    }
}