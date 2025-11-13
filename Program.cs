using Keycloak.AuthServices.Authentication;
using Keycloak.AuthServices.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using POCKeycloak.Application.Interfaces;
using POCKeycloak.Application.Services;
using POCKeycloak.Infrastructure.Interfaces;
using POCKeycloak.Infrastructure.Repositories;
using POCKeycloak.Properties;
using System.Security.Claims;


var builder = WebApplication.CreateBuilder(args);

// Keycloak configuration can be provided via appsettings.json or environment variables:
// Keycloak:Authority, Keycloak:ClientId, Keycloak:ClientSecret (optional)
var keycloakAuthority = builder.Configuration["Keycloak:Authority"] ?? "http://localhost:8080/realms/myrealm";
var keycloakAudience = builder.Configuration["Keycloak:ClientId"] ?? "dotnet-api";

//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
//})
//.AddJwtBearer(options =>
//{
//    options.Authority = keycloakAuthority;
//    options.Audience = keycloakAudience;
//    options.RequireHttpsMetadata = false; // Only for local/dev
//    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
//    {
//        NameClaimType = "preferred_username",
//        RoleClaimType = ClaimTypes.Role,
//        ValidateIssuer = true,
//        ValidIssuer = keycloakAuthority,
//        ValidateAudience = true,
//        AudienceValidator = (audiences, securityToken, validationParameters) =>
//        {
//            var azp = (securityToken as System.IdentityModel.Tokens.Jwt.JwtSecurityToken)?
//                        .Payload?
//                        .GetValueOrDefault("azp")?.ToString();

//            return audiences.Contains("account") || azp == "dotnet-api";
//        }
//    };

//});
builder.Services.AddHttpClient();

builder.Services
    .AddAuthentication("Keycloak")
    .AddScheme<AuthenticationSchemeOptions, KeycloakIntrospectionHandler>(
        "Keycloak", options => {  });


//builder.Services.AddKeycloakWebApiAuthentication(builder.Configuration, options =>
//{
//    options.RequireHttpsMetadata = false; // 🚨 disables HTTPS check
//});
//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    // Add OAuth2 Introspection handler
//    .AddOAuth2Introspection(options =>
//    {
//        // 🚨 CRITICAL: Pulls the configuration from the Keycloak section
//        var config = builder.Configuration.GetSection("Keycloak");

//        // 💡 These three values are mandatory for the server-to-server call to Keycloak's introspection endpoint
//        options.Authority = config["Authority"];
//        options.ClientId = config["ClientId"];
//        options.ClientSecret = config["ClientSecret"];

//        // Optional: Keycloak token validation only works over HTTPS by default.
//        // If you are developing locally with HTTP, you must disable this:
//        options.RequireHttpsMetadata = config.GetValue<bool>("RequireHttpsMetadata", true);

//        // Optional: Enable caching to avoid hitting Keycloak on every single request
//        options.EnableCaching = true;
//        options.CacheDuration = TimeSpan.FromMinutes(5); // Cache the validation for 5 minutes
//    });
builder.Services.AddAuthorization();

//builder.Services.AddKeycloakAuthorization(builder.Configuration);

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IUserRepository, UserRepository>();


builder.Services.AddControllers();

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // Add JWT bearer definition
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});
// Program.cs (before builder.Build())
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Ensure authentication runs before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
