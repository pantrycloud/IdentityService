using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using PantryCloud.IdentityService.Core;
using PantryCloud.IdentityService.Infrastructure.Services;
using Shouldly;

namespace PantryCloud.IdentityService.UnitTests.Auth;

public class TokenProviderTests
{
    private readonly TokenProvider _provider = new(BuildTestConfiguration());

    [Fact]
    public async Task CreateAccessToken_IsValid_AndContainsExpectedClaims()
    {
        var token = _provider.CreateAccessToken(Constants.ExampleUser);

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(token, BuildValidationParams());

        result.IsValid.ShouldBeTrue(result.Exception?.ToString());

        var identity = result.ClaimsIdentity!;
        identity.FindFirst("sub")!.Value.ShouldBe(Constants.ExampleUser.Id.ToString());
        identity.FindFirst("email")!.Value.ShouldBe(Constants.ExampleUser.Email);
        identity.FindFirst("email_verified")!.Value.ShouldBe(Constants.ExampleUser.EmailVerified.ToString());
    }

    [Fact]
    public async Task CreateAccessToken_Expiration_IsValid()
    {
        var token = _provider.CreateAccessToken(Constants.ExampleUser);

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(token, BuildValidationParams());

        result.IsValid.ShouldBeTrue(result.Exception?.ToString());

        var jwt = handler.ReadJsonWebToken(token);
        var expUnix = long.Parse(jwt.Claims.First(c => c.Type == "exp").Value);
        var expUtc = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;

        expUtc.ShouldBeGreaterThan(DateTime.UtcNow);
        expUtc.ShouldBeLessThanOrEqualTo(DateTime.UtcNow.AddMinutes(Constants.Jwt.ExpirationInMinutes + 1));
    }

    [Fact]
    public async Task CreateAccessToken_FailsValidation_WithWrongPublicKey()
    {
        var token = _provider.CreateAccessToken(Constants.ExampleUser);

        // Generate a different key for validation
        using var rsa = RSA.Create(2048);
        var wrongKey = new RsaSecurityKey(rsa);

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = Constants.Jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = Constants.Jwt.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = wrongKey,
            ClockSkew = TimeSpan.FromSeconds(5)
        });

        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public void CreateRefreshToken_Generates64ByteToken()
    {
        var refreshToken = _provider.CreateRefreshToken();
        var bytes = Convert.FromBase64String(refreshToken);
        bytes.Length.ShouldBe(64);
    }

    private static TokenValidationParameters BuildValidationParams()
    {
        var publicKey = File.ReadAllText(Constants.Jwt.PublicKeyPath);
        var rsa = RSA.Create();
        rsa.ImportFromPem(publicKey.ToCharArray());

        var securityKey = new RsaSecurityKey(rsa);

        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = Constants.Jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = Constants.Jwt.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ClockSkew = TimeSpan.FromSeconds(5)
        };
    }

    private static ApiConfiguration BuildTestConfiguration()
    {
        return new ApiConfiguration
        {
            Jwt = new JwtSettings
            {
                PrivateKeyPath = Constants.Jwt.PrivateKeyPath,
                Issuer = Constants.Jwt.Issuer,
                Audience = Constants.Jwt.Audience,
                ExpirationInMinutes = Constants.Jwt.ExpirationInMinutes,
            }
        };
    }
}