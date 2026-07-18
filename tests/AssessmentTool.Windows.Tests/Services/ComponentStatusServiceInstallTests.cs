using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Windows.Components;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ComponentStatusServiceInstallTests
{
    [Fact]
    public async Task Verified_local_package_is_copied_to_fixed_target_only_after_install_call()
    {
        using (var fixture = new InstallFixture())
        {
            var sourceBytes = CreateBytes("trusted-plink-fixture");
            var sourcePath = fixture.WriteSource(sourceBytes);
            var definition = fixture.CreateDefinition(sourceBytes);
            var service = new ComponentStatusService(
                fixture.ApplicationRoot,
                definition,
                () => AvailableStatus(definition, fixture.TargetPath));

            var preview = await service.PreparePlinkInstallAsync(sourcePath);

            Assert.False(File.Exists(fixture.TargetPath));
            Assert.Equal(Hash(sourceBytes), preview.Sha256);

            var status = await service.InstallPreparedPlinkAsync(preview);

            Assert.True(status.Available);
            Assert.Equal(sourceBytes, File.ReadAllBytes(fixture.TargetPath));
            Assert.Empty(Directory.GetFiles(fixture.TargetDirectory, ".plink-*"));
        }
    }

    [Fact]
    public async Task Wrong_hash_is_rejected_before_target_directory_is_created()
    {
        using (var fixture = new InstallFixture())
        {
            var sourcePath = fixture.WriteSource(CreateBytes("untrusted-file"));
            var expectedBytes = CreateBytes("different-trusted-file");
            var definition = fixture.CreateDefinition(expectedBytes);
            var service = new ComponentStatusService(
                fixture.ApplicationRoot,
                definition,
                () => AvailableStatus(definition, fixture.TargetPath));

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                service.PreparePlinkInstallAsync(sourcePath));

            Assert.False(Directory.Exists(fixture.TargetDirectory));
        }
    }

    [Fact]
    public async Task Failed_post_install_validation_restores_existing_component()
    {
        using (var fixture = new InstallFixture())
        {
            var originalBytes = CreateBytes("previous-component");
            var replacementBytes = CreateBytes("replacement-component");
            fixture.WriteTarget(originalBytes);
            var sourcePath = fixture.WriteSource(replacementBytes);
            var definition = fixture.CreateDefinition(replacementBytes);
            var service = new ComponentStatusService(
                fixture.ApplicationRoot,
                definition,
                () => UnavailableStatus(definition));
            var preview = await service.PreparePlinkInstallAsync(sourcePath);

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                service.InstallPreparedPlinkAsync(preview));

            Assert.Equal(originalBytes, File.ReadAllBytes(fixture.TargetPath));
            Assert.Empty(Directory.GetFiles(fixture.TargetDirectory, ".plink-*"));
        }
    }

    [Fact]
    public async Task Source_changed_after_preview_is_rejected_without_replacing_target()
    {
        using (var fixture = new InstallFixture())
        {
            var originalBytes = CreateBytes("previous-component");
            var trustedBytes = CreateBytes("trusted-component");
            fixture.WriteTarget(originalBytes);
            var sourcePath = fixture.WriteSource(trustedBytes);
            var definition = fixture.CreateDefinition(trustedBytes);
            var service = new ComponentStatusService(
                fixture.ApplicationRoot,
                definition,
                () => AvailableStatus(definition, fixture.TargetPath));
            var preview = await service.PreparePlinkInstallAsync(sourcePath);
            File.WriteAllBytes(sourcePath, CreateBytes("changed-after-confirmation"));

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                service.InstallPreparedPlinkAsync(preview));

            Assert.Equal(originalBytes, File.ReadAllBytes(fixture.TargetPath));
        }
    }

    private static ComponentStatus AvailableStatus(ComponentDefinition definition, string targetPath)
    {
        return new ComponentStatus(
            true,
            ComponentFailure.None,
            definition.Id,
            definition.AffectedFeature,
            "SSH连接组件可用。",
            "无需处理。",
            new ComponentFileIdentity(
                targetPath,
                definition.ExpectedSha256,
                1,
                DateTime.UtcNow,
                1,
                1,
                1),
            definition.DefinitionKey);
    }

    private static ComponentStatus UnavailableStatus(ComponentDefinition definition)
    {
        return new ComponentStatus(
            false,
            ComponentFailure.HashMismatch,
            definition.Id,
            definition.AffectedFeature,
            "SSH连接暂不可用。",
            "请重新安装。",
            null,
            definition.DefinitionKey);
    }

    private static byte[] CreateBytes(string value)
    {
        return System.Text.Encoding.UTF8.GetBytes(value);
    }

    private static string Hash(byte[] bytes)
    {
        using (var algorithm = SHA256.Create())
        {
            return BitConverter.ToString(algorithm.ComputeHash(bytes))
                .Replace("-", string.Empty)
                .ToLowerInvariant();
        }
    }

    private sealed class InstallFixture : IDisposable
    {
        internal InstallFixture()
        {
            ApplicationRoot = Path.Combine(
                Path.GetTempPath(),
                "EvaluationTool.ComponentInstall." + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(ApplicationRoot);
        }

        internal string ApplicationRoot { get; }
        internal string TargetDirectory => Path.Combine(ApplicationRoot, "依赖组件");
        internal string TargetPath => Path.Combine(TargetDirectory, "plink.exe");

        internal ComponentDefinition CreateDefinition(byte[] expectedBytes)
        {
            return ComponentDefinition.Plink(
                @"依赖组件\plink.exe",
                Hash(expectedBytes),
                "0.84.0.0");
        }

        internal string WriteSource(byte[] bytes)
        {
            var directory = Path.Combine(ApplicationRoot, "离线来源");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "plink.exe");
            File.WriteAllBytes(path, bytes);
            return path;
        }

        internal void WriteTarget(byte[] bytes)
        {
            Directory.CreateDirectory(TargetDirectory);
            File.WriteAllBytes(TargetPath, bytes);
        }

        public void Dispose()
        {
            if (Directory.Exists(ApplicationRoot))
            {
                Directory.Delete(ApplicationRoot, recursive: true);
            }
        }
    }
}
