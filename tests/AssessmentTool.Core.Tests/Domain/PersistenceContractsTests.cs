using System;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Domain;

public sealed class PersistenceContractsTests
{
    private const string FixtureSecret = "task5-secret-7e036b85-4183-4dfe-90e6-b61a86ff2ef1";
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void Strongly_typed_ids_use_canonical_guid_format()
    {
        var projectId = ProjectId.New();
        var deviceId = DeviceId.New();
        var credentialReference = CredentialReference.New();

        Assert.Equal(projectId.Value.ToString("D"), projectId.ToString());
        Assert.Equal(deviceId.Value.ToString("D"), deviceId.ToString());
        Assert.Equal(credentialReference.Value.ToString("D"), credentialReference.ToString());
        Assert.Throws<ArgumentException>(() => ProjectId.Parse(Guid.NewGuid().ToString("N")));
        Assert.Throws<ArgumentException>(() => DeviceId.Parse("not-a-guid"));
        Assert.Throws<ArgumentException>(() => CredentialReference.Parse(FixtureSecret));
        Assert.Throws<ArgumentException>(() => CredentialReference.Parse(Guid.NewGuid().ToString("N")));
    }

    [Fact]
    public void Default_strongly_typed_ids_cannot_be_accessed_or_stored()
    {
        var projectId = default(ProjectId);
        var deviceId = default(DeviceId);
        var credentialReference = default(CredentialReference);

        Assert.Throws<InvalidOperationException>(() => projectId.ToString());
        Assert.Throws<InvalidOperationException>(() => _ = projectId.Value);
        Assert.Throws<InvalidOperationException>(() => deviceId.ToString());
        Assert.Throws<InvalidOperationException>(() => _ = deviceId.Value);
        Assert.Throws<InvalidOperationException>(() => credentialReference.ToString());
        Assert.Throws<InvalidOperationException>(() => _ = credentialReference.Value);
        Assert.Throws<ArgumentException>(() => new ProjectRecord(projectId, "客户A", "项目A", @"C:\Evidence\项目A", DateTimeOffset.UtcNow));
        Assert.Throws<ArgumentException>(() => new DeviceRecord(
            DeviceId.New(), ProjectId.New(), "交换机A", "192.0.2.10", 22, credentialReference, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Persistence_dtos_validate_required_values_and_are_immutable()
    {
        var projectId = ProjectId.New();
        var deviceId = DeviceId.New();
        var credentialReference = CredentialReference.New();
        var project = new ProjectRecord(projectId, "客户A", "项目A", @"C:\\Evidence\\项目A", DateTimeOffset.UtcNow);
        var device = new DeviceRecord(deviceId, projectId, "交换机A", "192.0.2.10", 22, credentialReference, DateTimeOffset.UtcNow);

        Assert.Equal("客户A", project.CustomerName);
        Assert.Equal(credentialReference, device.CredentialReference);
        Assert.All(typeof(ProjectRecord).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.All(typeof(DeviceRecord).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.Throws<ArgumentException>(() => new DeviceRecord(
            deviceId, projectId, "", "192.0.2.10", 22, credentialReference, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Device_record_preserves_connection_identity_without_storing_a_secret()
    {
        var record = new DeviceRecord(
            DeviceId.New(),
            ProjectId.New(),
            "核心交换机",
            "192.0.2.10",
            22,
            "audit-reader",
            TargetCategory.NetworkDevice,
            ConnectionProtocol.Ssh,
            CredentialReference.New(),
            DateTimeOffset.UtcNow);

        Assert.Equal("audit-reader", record.UserName);
        Assert.Equal(TargetCategory.NetworkDevice, record.Category);
        Assert.Equal(ConnectionProtocol.Ssh, record.Protocol);
        Assert.Throws<ArgumentException>(() => new DeviceRecord(
            DeviceId.New(), ProjectId.New(), "设备", "192.0.2.11", 22, " ",
            TargetCategory.Automatic, ConnectionProtocol.Ssh, CredentialReference.New(), DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Evidence_file_record_validates_ids_kind_hash_ordinal_and_basic_relative_path()
    {
        var projectId = ProjectId.New();
        var deviceId = DeviceId.New();
        var record = new EvidenceFileRecord(
            projectId, deviceId, @"screens\page-1.png", Hash, EvidenceFileKind.EvidenceImage, 1, DateTimeOffset.UtcNow);

        Assert.Equal(1, record.Ordinal);
        Assert.Throws<ArgumentException>(() => new EvidenceFileRecord(
            default(ProjectId), deviceId, "page.png", Hash, EvidenceFileKind.EvidenceImage, 0, DateTimeOffset.UtcNow));
        Assert.Throws<ArgumentOutOfRangeException>(() => new EvidenceFileRecord(
            projectId, deviceId, "page.png", Hash, (EvidenceFileKind)99, 0, DateTimeOffset.UtcNow));
        Assert.Throws<ArgumentOutOfRangeException>(() => new EvidenceFileRecord(
            projectId, deviceId, "page.png", Hash, EvidenceFileKind.EvidenceImage, -1, DateTimeOffset.UtcNow));
        Assert.Throws<ArgumentException>(() => new EvidenceFileRecord(
            projectId, deviceId, @"..\page.png", Hash, EvidenceFileKind.EvidenceImage, 0, DateTimeOffset.UtcNow));
        Assert.Throws<ArgumentException>(() => new EvidenceFileRecord(
            projectId, deviceId, "page.png", "invalid", EvidenceFileKind.EvidenceImage, 0, DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData(@"C:\absolute.txt")]
    [InlineData(@"C:drive-relative.txt")]
    [InlineData(@"\\server\share\file.txt")]
    [InlineData(@"\\?\C:\file.txt")]
    [InlineData("file.txt:stream")]
    [InlineData("%2e%2e\\file.txt")]
    [InlineData("folder\u001ffile.txt")]
    [InlineData(@"folder\\file.txt")]
    [InlineData(@"folder\.\file.txt")]
    [InlineData(@"folder\..\file.txt")]
    [InlineData(@"folder.\file.txt")]
    [InlineData("folder \\file.txt")]
    [InlineData("CON.txt")]
    [InlineData("lPt1.LoG")]
    [InlineData("COM¹.txt")]
    [InlineData("com².LOG")]
    [InlineData("CoM³")]
    [InlineData("LPT¹.txt")]
    [InlineData("lpt².LOG")]
    [InlineData("LpT³")]
    [InlineData("bad?.txt")]
    public void Windows_evidence_relative_path_policy_rejects_unsafe_lexical_paths(string path)
    {
        Assert.Throws<ArgumentException>(() => WindowsEvidenceRelativePathPolicy.Normalize(path, nameof(path)));
        Assert.Throws<ArgumentException>(() => new EvidenceFileRecord(
            ProjectId.New(), DeviceId.New(), path, Hash, EvidenceFileKind.EvidenceImage, 0, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Windows_evidence_relative_path_policy_normalizes_separator_independently_of_host_os()
    {
        var normalized = WindowsEvidenceRelativePathPolicy.Normalize("screens/page-1.png", "path");
        var record = new EvidenceFileRecord(
            ProjectId.New(), DeviceId.New(), "screens/page-1.png", Hash, EvidenceFileKind.EvidenceImage, 0, DateTimeOffset.UtcNow);

        Assert.Equal(@"screens\page-1.png", normalized);
        Assert.Equal(normalized, record.RelativePath);
    }

    [Fact]
    public void Windows_evidence_relative_path_policy_rejects_every_c0_control_character()
    {
        for (var codePoint = 0; codePoint <= 0x1f; codePoint++)
        {
            var path = "folder" + (char)codePoint + "file.txt";
            Assert.Throws<ArgumentException>(() => WindowsEvidenceRelativePathPolicy.Normalize(path, nameof(path)));
            Assert.Throws<ArgumentException>(() => new EvidenceFileRecord(
                ProjectId.New(), DeviceId.New(), path, Hash, EvidenceFileKind.EvidenceImage, 0, DateTimeOffset.UtcNow));
        }
    }
}
