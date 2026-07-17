using System;
using System.Linq;
using AssessmentTool.Windows.Credentials;
using Xunit;

namespace AssessmentTool.Windows.Tests.Credentials;

public sealed class PpkPrivateKeyMaterialTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void Accepts_only_unencrypted_well_formed_ppk_versions(int version)
    {
        PpkPrivateKeyMaterial.Validate(CreatePpk(version).ToCharArray());
    }

    [Theory]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")]
    [InlineData("PuTTY-User-Key-File-1: ssh-rsa\nEncryption: none")]
    public void Rejects_non_ppk_and_unsupported_ppk_formats(string material)
    {
        var exception = Assert.Throws<PpkPrivateKeyException>(
            () => PpkPrivateKeyMaterial.Validate(material.ToCharArray()));

        Assert.Equal(PpkPrivateKeyFailure.UnsupportedFormat, exception.Failure);
        Assert.DoesNotContain("AAAA", exception.ToString());
    }

    [Fact]
    public void Rejects_passphrase_encrypted_ppk()
    {
        var material = CreatePpk(3).Replace("Encryption: none", "Encryption: aes256-cbc");

        var exception = Assert.Throws<PpkPrivateKeyException>(
            () => PpkPrivateKeyMaterial.Validate(material.ToCharArray()));

        Assert.Equal(PpkPrivateKeyFailure.Encrypted, exception.Failure);
        Assert.DoesNotContain("aes256-cbc", exception.ToString());
    }

    [Theory]
    [InlineData("\0")]
    [InlineData("\t")]
    [InlineData("\r")]
    [InlineData("\uFEFF")]
    public void Rejects_abnormal_text_without_disclosing_material(string abnormal)
    {
        var material = CreatePpk(2).Replace("Comment: test", "Comment: te" + abnormal + "st");

        var exception = Assert.Throws<PpkPrivateKeyException>(
            () => PpkPrivateKeyMaterial.Validate(material.ToCharArray()));

        Assert.Equal(PpkPrivateKeyFailure.InvalidText, exception.Failure);
        Assert.DoesNotContain("Private-Lines", exception.ToString());
    }

    [Fact]
    public void Rejects_material_over_the_encoded_size_limit()
    {
        var oversized = Enumerable.Repeat('A', PpkPrivateKeyMaterial.MaximumEncodedBytes + 1).ToArray();

        var exception = Assert.Throws<PpkPrivateKeyException>(
            () => PpkPrivateKeyMaterial.Validate(oversized));

        Assert.Equal(PpkPrivateKeyFailure.TooLarge, exception.Failure);
    }

    [Theory]
    [InlineData("Public-Lines: 1", "Public-Lines: 2")]
    [InlineData("QUJDRA==", "QUJDRA=!")]
    [InlineData("Private-MAC: 0000000000000000000000000000000000000000", "Private-MAC: 0000")]
    public void Rejects_invalid_ppk_structure(string original, string replacement)
    {
        var material = CreatePpk(2).Replace(original, replacement);

        var exception = Assert.Throws<PpkPrivateKeyException>(
            () => PpkPrivateKeyMaterial.Validate(material.ToCharArray()));

        Assert.Equal(PpkPrivateKeyFailure.InvalidStructure, exception.Failure);
    }

    internal static string CreatePpk(int version)
    {
        var mac = version == 2 ? new string('0', 40) : new string('0', 64);
        return
            "PuTTY-User-Key-File-" + version + ": ssh-rsa\r\n" +
            "Encryption: none\r\n" +
            "Comment: test\r\n" +
            "Public-Lines: 1\r\n" +
            "QUJDRA==\r\n" +
            "Private-Lines: 1\r\n" +
            "RUZHSA==\r\n" +
            "Private-MAC: " + mac + "\r\n";
    }
}
