using JobPortal.Services;

namespace JobPortal.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void HashPassword_ReturnsHash_ForValidPassword()
    {
        // Arrange
        var password = "StrongP@ssw0rd!";

        // Act
        var hash = PasswordHasher.HashPassword(password);

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(hash));
        Assert.StartsWith("$2", hash); // BCrypt hashes start with $2*
        Assert.True(hash.Length >= 50); // Typical BCrypt hash length is 60
    }

    [Fact]
    public void HashPassword_ProducesDifferentHashes_ForSamePassword()
    {
        // Arrange
        var password = "SamePassword";

        // Act
        var hash1 = PasswordHasher.HashPassword(password);
        var hash2 = PasswordHasher.HashPassword(password);

        // Assert
        Assert.NotEqual(hash1, hash2); // Different salts should produce different hashes
        Assert.True(PasswordHasher.VerifyPassword(password, hash1));
        Assert.True(PasswordHasher.VerifyPassword(password, hash2));
    }

    [Fact]
    public void VerifyPassword_ReturnsTrue_ForMatchingPasswordAndHash()
    {
        // Arrange
        var password = "MatchThis1!";
        var hash = PasswordHasher.HashPassword(password);

        // Act
        var result = PasswordHasher.VerifyPassword(password, hash);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void VerifyPassword_ReturnsFalse_ForWrongPassword()
    {
        // Arrange
        var password = "Correct#123";
        var wrongPassword = "Wrong#123";
        var hash = PasswordHasher.HashPassword(password);

        // Act
        var result = PasswordHasher.VerifyPassword(wrongPassword, hash);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void HashPassword_ThrowsArgumentNullException_ForNullPassword()
    {
        // Arrange
        string? password = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => PasswordHasher.HashPassword(password!));
    }
}