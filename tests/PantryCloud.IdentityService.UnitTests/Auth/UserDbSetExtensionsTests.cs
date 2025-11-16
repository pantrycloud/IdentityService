using Microsoft.EntityFrameworkCore;
using PantryCloud.IdentityService.Core.Entities;
using PantryCloud.IdentityService.Infrastructure;
using Shouldly;

namespace PantryCloud.IdentityService.UnitTests.Auth;

public class UserDbSetExtensionsTests
{
    private sealed class TestDbContext(DbContextOptions<TestDbContext> options) : DbContext(options)
    {
        public DbSet<ApplicationUser> Users => Set<ApplicationUser>();
    }

    private static TestDbContext CreateContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<TestDbContext>()
            .UseInMemoryDatabase(databaseName: dbName)
            .Options;
        
        return new TestDbContext(options);
    }

    [Fact]
    public async Task Exists_ReturnsTrue_WhenEmailExists()
    {
        var ctx = CreateContext(nameof(Exists_ReturnsTrue_WhenEmailExists));

        ctx.Users.Add(Constants.ExampleUser);
        await ctx.SaveChangesAsync();

        var exists = await ctx.Users.Exists(Constants.ExampleUser.Email);

        exists.ShouldBeTrue();
    }

    [Fact]
    public async Task Exists_ReturnsFalse_WhenEmailMissing()
    {
        var ctx = CreateContext(nameof(Exists_ReturnsFalse_WhenEmailMissing));

        var exists = await ctx.Users.Exists("nobody@example.com");

        exists.ShouldBeFalse();
    }

    [Fact]
    public async Task GetByEmail_ReturnsUser_WhenEmailMatches()
    {
        var ctx = CreateContext(nameof(GetByEmail_ReturnsUser_WhenEmailMatches));

        ctx.Users.Add(Constants.ExampleUser);
        await ctx.SaveChangesAsync();

        var result = await ctx.Users.GetByEmail(Constants.ExampleUser.Email);

        result.ShouldNotBeNull();
        result!.Id.ShouldBe(Constants.ExampleUser.Id);
        result.Email.ShouldBe(Constants.ExampleUser.Email);
    }

    [Fact]
    public async Task GetByEmail_ReturnsNull_WhenNotFound()
    {
        var ctx = CreateContext(nameof(GetByEmail_ReturnsNull_WhenNotFound));

        var result = await ctx.Users.GetByEmail("missing@example.com");

        result.ShouldBeNull();
    }
}