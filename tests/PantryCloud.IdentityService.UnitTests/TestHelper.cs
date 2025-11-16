using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NSubstitute;
using PantryCloud.IdentityService.Application;
using PantryCloud.IdentityService.Core;
using PantryCloud.IdentityService.Core.Entities;
using PantryCloud.IdentityService.Infrastructure;
using PantryCloud.IdentityService.Infrastructure.Persistence;
using PantryCloud.IdentityService.Infrastructure.Services;

namespace PantryCloud.IdentityService.UnitTests;

internal static class TestHelper
{
    public static ApplicationDbContext CreateInMemoryContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(dbName)
            .Options;
        return new ApplicationDbContext(options);
    }

    public static ITokenProvider MockTokenProvider(string accessToken = "ACCESS_TOKEN",
        string refreshToken = "REFRESH_TOKEN",
        string passwordResetToken = "PASSWORD_RESET_TOKEN")
    {
        var tp = Substitute.For<ITokenProvider>();
        tp.CreateAccessToken(Arg.Any<ApplicationUser>()).Returns(accessToken);
        tp.CreateRefreshToken().Returns(refreshToken);
        tp.CreatePasswordResetToken().Returns(passwordResetToken);

        return tp;
    }

    public static ApiConfiguration MockConfiguration()
    {
        var tp = new ApiConfiguration();
        return tp;
    }

    public static ILogger<AuthService> MockLogger()
        => Substitute.For<ILogger<AuthService>>();

    public static ApplicationUser MakeUser(string email, string password, bool verified = false)
    {
        return new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = email,
            EmailVerified = verified,
            PasswordHash = PasswordHasher.Hash(password)
        };
    }
    
    public static ResetPasswordToken MakeResetToken(string email, bool used = false, bool expired = false)
    {
        return new ResetPasswordToken
        {
            Id = Guid.NewGuid(),
            Email = email,
            Token = Guid.NewGuid().ToString(),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expired ? DateTime.UtcNow.AddMinutes(-5) : DateTime.UtcNow.AddMinutes(10),
            UsedAt = used ? DateTime.UtcNow : null
        };
    }
    
    public static VerifyEmailToken MakeVerifyEmailToken(string email, bool used = false, bool expired = false)
    {
        return new VerifyEmailToken
        {
            Id = Guid.NewGuid(),
            Email = email,
            Token = Guid.NewGuid().ToString(),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expired ? DateTime.UtcNow.AddMinutes(-5) : DateTime.UtcNow.AddMinutes(10),
            UsedAt = used ? DateTime.UtcNow : null
        };
    }
}