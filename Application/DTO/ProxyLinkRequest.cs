namespace POCKeycloak.Application.DTO
{
 public class ProxyLinkRequest
 {
 public string FirstName { get; set; } = string.Empty;
 public string LastName { get; set; } = string.Empty;
 public string Email { get; set; } = string.Empty;
 // ISO8601 date/time expected. Server will validate.
 public DateTimeOffset Expiry { get; set; }
 // Optional return URL that will receive the token as a query parameter
 public string? ReturnUrl { get; set; }
 }
}
