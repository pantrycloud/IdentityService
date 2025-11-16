using PantryCloud.IdentityService.Infrastructure;
using Shouldly;

namespace PantryCloud.IdentityService.UnitTests.Auth;

public class PasswordHasherTests
{
    [Fact]
    public void Hash_ProducesDifferentHashes_ForSamePassword_DueToRandomSalt()
    {
        var hash1 = PasswordHasher.Hash(Constants.ExamplePassword);
        var hash2 = PasswordHasher.Hash(Constants.ExamplePassword);

        hash1.ShouldNotBe(hash2);
        hash1.ShouldContain("-");
        hash2.ShouldContain("-");
    }

    [Fact]
    public void Verify_ReturnsTrue_ForCorrectPassword()
    {
        var hash = PasswordHasher.Hash(Constants.ExamplePassword);

        var ok = PasswordHasher.Verify(Constants.ExamplePassword, hash);

        ok.ShouldBeTrue();
    }

    [Fact]
    public void Verify_ReturnsFalse_ForWrongPassword()
    {
        var rightHash = PasswordHasher.Hash(Constants.ExamplePassword);

        var ok = PasswordHasher.Verify("WrongPassword", rightHash);

        ok.ShouldBeFalse();
    }

    [Fact]
    public void Hash_Format_IsHashDashSalt_InHex_WithExpectedLengths()
    {
        var combined = PasswordHasher.Hash(Constants.ExamplePassword);

        var parts = combined.Split('-');
        parts.Length.ShouldBe(2);

        var hashBytes = Convert.FromHexString(parts[0]);
        var saltBytes = Convert.FromHexString(parts[1]);

        hashBytes.Length.ShouldBe(32); // HashSize
        saltBytes.Length.ShouldBe(16); // SaltSize
    }

    [Fact]
    public void Verify_Throws_OnMalformedStoredHash_NoDash()
    {
        const string malformed = "ABCDEF"; // no '-' separator

        Should.Throw<IndexOutOfRangeException>(() =>
        {
            PasswordHasher.Verify("anything", malformed);
        });
    }

    [Fact]
    public void Verify_Throws_OnMalformedStoredHash_NonHex()
    {
        var malformed = "NOTHEX-ALSOnotHEX";

        Should.Throw<FormatException>(() =>
        {
            PasswordHasher.Verify("anything", malformed);
        });
    }
}