using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PantryCloud.IdentityService.Application;
using PantryCloud.IdentityService.Application.DTOs;
using PantryCloud.IdentityService.Core;
using PantryCloud.IdentityService.Core.Errors;
using PantryCloud.IdentityService.Infrastructure.Services;
using Shouldly;

namespace PantryCloud.IdentityService.UnitTests.Auth;

public class AuthServiceTests
{
    private readonly ILogger<AuthService> _loggerMock = TestHelper.MockLogger();
    private readonly ITokenProvider  _tokenProviderMock = TestHelper.MockTokenProvider();
    private readonly ApiConfiguration _configurationMock = TestHelper.MockConfiguration();

    [Fact]
    public async Task RegisterAsync_ShouldCreateUser_AndReturnId_WhenNewEmail()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(RegisterAsync_ShouldCreateUser_AndReturnId_WhenNewEmail));
        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var request = new RegisterRequestDto(Constants.ExampleUser.Email, Constants.StrongPassword);

        var result = await authService.RegisterAsync(request, CancellationToken.None);

        result.IsError.ShouldBeFalse();
        result.Value.UserId.ShouldNotBeNullOrWhiteSpace();

        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == request.Email);
        user.ShouldNotBeNull();
        user!.EmailVerified.ShouldBeFalse();
        user.PasswordHash.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task RegisterAsync_ShouldReturnError_WhenEmailAlreadyExists()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(RegisterAsync_ShouldReturnError_WhenEmailAlreadyExists));
        var existing = Constants.ExampleUser;
        db.Users.Add(existing);
        await db.SaveChangesAsync();
        
        var authService = new AuthService(_tokenProviderMock, db, _loggerMock,  _configurationMock);

        var request = new RegisterRequestDto(existing.Email, Constants.ExamplePassword);

        var result = await authService.RegisterAsync(request, CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.RegistrationUserAlreadyExists(existing.Email));
    }
    
    [Fact]
    public async Task LoginAsync_ShouldReturnTokens_AndPersistRefreshToken_OnValidCredentials()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(LoginAsync_ShouldReturnTokens_AndPersistRefreshToken_OnValidCredentials));
        var user = TestHelper.MakeUser(Constants.ExampleUser.Email, Constants.StrongPassword, verified: true);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var tokenProvider = TestHelper.MockTokenProvider(accessToken: "AT", refreshToken: "RT");
        var authService = new AuthService(tokenProvider, db, _loggerMock, _configurationMock);

        var request = new LoginRequestDto(user.Email, Constants.StrongPassword);

        var result = await authService.LoginAsync(request, CancellationToken.None);

        result.IsError.ShouldBeFalse();
        result.Value.AccessToken.ShouldBe("AT");
        result.Value.RefreshToken.ShouldBe("RT");

        var reloaded = await db.Users.SingleAsync(u => u.Id == user.Id);
        reloaded.RefreshToken.ShouldBe("RT");
        reloaded.RefreshTokenExpiryTime.ShouldNotBeNull();
        reloaded.RefreshTokenExpiryTime!.Value.ShouldBeGreaterThan(DateTime.UtcNow);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnError_WhenUserNotFound()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(LoginAsync_ShouldReturnError_WhenUserNotFound));
        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.LoginAsync(
            new LoginRequestDto(Constants.ExampleUser.Email, "x"), 
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.LoginInvalidCredentials);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnError_WhenPasswordInvalid()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(LoginAsync_ShouldReturnError_WhenPasswordInvalid));
        var user = Constants.ExampleUser;
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var tokenProvider = TestHelper.MockTokenProvider();
        var logger = TestHelper.MockLogger();
        var authService = new AuthService(tokenProvider, db, logger,  _configurationMock);

        var result = await authService.LoginAsync(
            new LoginRequestDto(user.Email, "Wrong#123"),
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.LoginInvalidCredentials);
    }


    [Fact]
    public async Task RefreshTokenAsync_ShouldIssueNewTokens_AndRotateRefreshToken_WhenValid()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(RefreshTokenAsync_ShouldIssueNewTokens_AndRotateRefreshToken_WhenValid));
        var user = Constants.ExampleUser;
        user.RefreshToken = "OLD_RT";
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(1);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var tokenProvider = TestHelper.MockTokenProvider(accessToken: "NEW_AT", refreshToken: "NEW_RT");
        var authService = new AuthService(tokenProvider, db, _loggerMock, _configurationMock);

        var result = await authService.RefreshTokenAsync(
            new RefreshTokenRequestDto("OLD_RT"), 
            CancellationToken.None);

        result.IsError.ShouldBeFalse();
        result.Value.AccessToken.ShouldBe("NEW_AT");
        result.Value.RefreshToken.ShouldBe("NEW_RT");

        var reloaded = await db.Users.SingleAsync(u => u.Id == user.Id);
        reloaded.RefreshToken.ShouldBe("NEW_RT");
        reloaded.RefreshTokenExpiryTime.ShouldNotBeNull();
        reloaded.RefreshTokenExpiryTime!.Value.ShouldBeGreaterThan(DateTime.UtcNow);
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnError_WhenTokenNotFound()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(RefreshTokenAsync_ShouldReturnError_WhenTokenNotFound));
        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.RefreshTokenAsync(
            new RefreshTokenRequestDto("NON_EXISTENT"), 
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.InvalidRefreshToken);
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnError_WhenTokenExpired()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(RefreshTokenAsync_ShouldReturnError_WhenTokenExpired));
        var user = Constants.ExampleUser;
        user.RefreshToken = "EXPIRED_RT";
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(-1);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        
        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.RefreshTokenAsync(
            new RefreshTokenRequestDto("EXPIRED_RT"), 
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.ExpiredRefreshToken);
    }
    
    [Fact]
    public async Task ForgotPasswordAsync_ShouldGenerateTokenAndReturnCallback_WhenUserExists()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(ForgotPasswordAsync_ShouldGenerateTokenAndReturnCallback_WhenUserExists));
        var user = Constants.ExampleUser;
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.ForgotPasswordAsync(
            new ForgotPasswordRequestDto(user.Email), CancellationToken.None);

        result.IsError.ShouldBeFalse();
        result.Value.Token.ShouldNotBeEmpty();
        result.Value.Url.ShouldContain("reset-password?email=");
        var tokenEntity = await db.ResetPasswordTokens.SingleOrDefaultAsync(t => t.Email == user.Email);
        tokenEntity.ShouldNotBeNull();
    }
    
    [Fact]
    public async Task ForgotPasswordAsync_ShouldReturnError_WhenUserDoesNotExist()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(ForgotPasswordAsync_ShouldReturnError_WhenUserDoesNotExist));
        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.ForgotPasswordAsync(new ForgotPasswordRequestDto("notfound@example.com"), CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.UserDoesNotExist("notfound@example.com"));
    }
    
    [Fact]
    public async Task ResetPasswordAsync_ShouldResetPassword_WhenTokenValid()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(ResetPasswordAsync_ShouldResetPassword_WhenTokenValid));
        var user = TestHelper.MakeUser("user@example.com", Constants.StrongPassword);
        var token = TestHelper.MakeResetToken(user.Email, used: false, expired: false);

        var originalPassword = user.PasswordHash;
        
        db.Users.Add(user);
        db.ResetPasswordTokens.Add(token);
        await db.SaveChangesAsync();

        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.ResetPasswordAsync(
            new ResetPasswordRequestDto(user.Email, token.Token, "NewPass123!"), CancellationToken.None);

        result.IsError.ShouldBeFalse();
        var updatedUser = await db.Users.SingleAsync(u => u.Email == user.Email);
        updatedUser.PasswordHash.ShouldNotBe(originalPassword);
    }
    
    [Fact]
    public async Task ResetPasswordAsync_ShouldReturnError_WhenTokenIsUsed()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(ResetPasswordAsync_ShouldReturnError_WhenTokenIsUsed));
        var user = Constants.ExampleUser;
        var token = TestHelper.MakeResetToken(user.Email, used: true);
        db.Users.Add(user);
        db.ResetPasswordTokens.Add(token);
        await db.SaveChangesAsync();

        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.ResetPasswordAsync(new ResetPasswordRequestDto(user.Email, token.Token, "newPass123!"), CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.TokenAlreadyUsed);
    }
    
    [Fact]
    public async Task ResetPasswordAsync_ShouldReturnError_WhenTokenIsExpired()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(ResetPasswordAsync_ShouldReturnError_WhenTokenIsExpired));
        var user = Constants.ExampleUser;
        var token = TestHelper.MakeResetToken(user.Email, used: false, expired: true);
        db.Users.Add(user);
        db.ResetPasswordTokens.Add(token);
        await db.SaveChangesAsync();

        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.ResetPasswordAsync(
            new ResetPasswordRequestDto(user.Email, token.Token, "newPass123!"), CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.TokenExpired);
    }
    
    [Fact]
    public async Task ResetPasswordAsync_ShouldReturnError_WhenTokenIsInvalid()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(ResetPasswordAsync_ShouldReturnError_WhenTokenIsInvalid));
        var user = Constants.ExampleUser;
        var token = TestHelper.MakeResetToken(user.Email, used: false, expired: false);
        db.Users.Add(user);
        // Do not add the token to db
        await db.SaveChangesAsync();

        var authService = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await authService.ResetPasswordAsync(
            new ResetPasswordRequestDto(user.Email, token.Token, "newPass123!"), CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.TokenNotValid);
    }
    
    [Fact]
    public async Task VerifyEmailAsync_ShouldVerifyEmail_WhenTokenIsValid()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(VerifyEmailAsync_ShouldVerifyEmail_WhenTokenIsValid));
        var user = Constants.ExampleUser;
        var token = TestHelper.MakeVerifyEmailToken(user.Email, used: false, expired: false);

        db.Users.Add(user);
        db.VerifyEmailTokens.Add(token);
        await db.SaveChangesAsync();

        var service = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await service.VerifyEmailAsync(new VerifyEmailRequestDto(user.Email, token.Token), CancellationToken.None);

        result.IsError.ShouldBeFalse();

        var updatedUser = await db.Users.SingleAsync(u => u.Email == user.Email);
        updatedUser.EmailVerified.ShouldBeTrue();

        var updatedToken = await db.VerifyEmailTokens.SingleAsync(t => t.Email == user.Email);
        updatedToken.UsedAt.ShouldNotBeNull();
    }
    
    [Fact]
    public async Task VerifyEmailAsync_ShouldReturnError_WhenUserNotFound()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(VerifyEmailAsync_ShouldReturnError_WhenUserNotFound));
        var token = TestHelper.MakeVerifyEmailToken("notfound@example.com");

        db.VerifyEmailTokens.Add(token);
        await db.SaveChangesAsync();

        var service = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await service.VerifyEmailAsync(
            new VerifyEmailRequestDto("notfound@example.com", token.Token),
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.UserDoesNotExist("notfound@example.com"));
    }
    
    [Fact]
    public async Task VerifyEmailAsync_ShouldReturnError_WhenTokenNotFound()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(VerifyEmailAsync_ShouldReturnError_WhenTokenNotFound));
        var user = Constants.ExampleUser;
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var service = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await service.VerifyEmailAsync(
            new VerifyEmailRequestDto(user.Email, "invalid-token"),
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.TokenNotValid);
    }
    
    [Fact]
    public async Task VerifyEmailAsync_ShouldReturnError_WhenTokenAlreadyUsed()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(VerifyEmailAsync_ShouldReturnError_WhenTokenAlreadyUsed));
        var user = Constants.ExampleUser;
        var token = TestHelper.MakeVerifyEmailToken(user.Email, used: true);

        db.Users.Add(user);
        db.VerifyEmailTokens.Add(token);
        await db.SaveChangesAsync();

        var service = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await service.VerifyEmailAsync(
            new VerifyEmailRequestDto(user.Email, token.Token),
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.TokenAlreadyUsed);
    }
    
    [Fact]
    public async Task VerifyEmailAsync_ShouldReturnError_WhenTokenExpired()
    {
        await using var db = TestHelper.CreateInMemoryContext(nameof(VerifyEmailAsync_ShouldReturnError_WhenTokenExpired));
        var user = Constants.ExampleUser;
        var token = TestHelper.MakeVerifyEmailToken(user.Email, expired: true);

        db.Users.Add(user);
        db.VerifyEmailTokens.Add(token);
        await db.SaveChangesAsync();

        var service = new AuthService(_tokenProviderMock, db, _loggerMock, _configurationMock);

        var result = await service.VerifyEmailAsync(
            new VerifyEmailRequestDto(user.Email, token.Token),
            CancellationToken.None);

        result.IsError.ShouldBeTrue();
        result.Errors.ShouldContain(AuthErrors.TokenExpired);
    }
}


