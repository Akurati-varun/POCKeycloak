using Microsoft.AspNetCore.Authentication;
using Microsoft.OpenApi.Models;
using POCKeycloak.Application.Interfaces;
using POCKeycloak.Application.Services;
using POCKeycloak.Infrastructure.Interfaces;
using POCKeycloak.Infrastructure.Repositories;
using POCKeycloak.Properties;


var builder = WebApplication.CreateBuilder(args);


builder.Services.AddHttpClient();

builder.Services
    .AddAuthentication("Keycloak")
    .AddScheme<AuthenticationSchemeOptions, KeycloakIntrospectionHandler>(
        "Keycloak", options => {  });

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

//app.UseHttpsRedirection();

// Ensure authentication runs before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
