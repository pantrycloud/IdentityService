using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using PantryCloud.IdentityService.Core.Entities;
using PantryCloud.IdentityService.Infrastructure;

namespace PantryCloud.IdentityService.UnitTests;

internal static class Constants
{
    public static readonly ApplicationUser ExampleUser = new()
    {
        Id = Guid.NewGuid(),
        Email = "alice@example.com",
        EmailVerified = true,
        PasswordHash = PasswordHasher.Hash("password")
    };

    public const string StrongPassword = "StrongPass#1"; 

    public const string ExamplePassword = "password";

    public static class Jwt
    {
        public const string Secret = "CORRECT_SECRET_KEY_32+_CHARS________________";
        public const string BadSecret = "BAD_SECRET_KEY_32+_CHARS___________________";
        public const string Issuer = "PantryCloud.IdentityService";
        public const string Audience = "PantryCloud.WebClient";
        public const int ExpirationInMinutes = 5;
        public const string PublicKeyPath = "Auth/Certs/jwt-public.pem";
        public const string PrivateKeyPath = "Auth/Certs/jwt-private.pem";

        public static readonly IConfiguration Config =
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Jwt:Secret"] = Secret,
                    ["Jwt:Issuer"] = Issuer,
                    ["Jwt:Audience"] = Audience,
                    ["Jwt:ExpirationInMinutes"] = ExpirationInMinutes.ToString()
                }!)
                .Build();
    }
}