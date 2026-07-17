using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ProjectEvidencePackageExporterTests
{
    [Fact]
    public void Zip_entry_names_are_relative_normalized_and_unicode_stable()
    {
        Assert.Equal(
            "evidence/设备甲/证据.png",
            ProjectEvidencePackageExporter.CreateEntryName(@"设备甲\证据.png"));
        Assert.Equal(
            ProjectEvidencePackageExporter.CreateEntryName("设备/e\u0301vidence.txt"),
            ProjectEvidencePackageExporter.CreateEntryName("设备/évidence.txt"));
        Assert.Throws<ArgumentException>(() =>
            ProjectEvidencePackageExporter.CreateEntryName(@"..\outside.txt"));
        Assert.Throws<ArgumentException>(() =>
            ProjectEvidencePackageExporter.CreateEntryName(@"C:\outside.txt"));
    }

    [Fact]
    public async Task Export_packages_manifest_and_only_verified_indexed_evidence()
    {
        using (var fixture = new PackageFixture())
        {
            var exporter = fixture.CreateExporter(EvidenceShaStatus.Verified);
            var destination = Path.Combine(fixture.ExportDirectory, "项目甲-证据包.zip");

            var result = await exporter.ExportAsync(fixture.Project, destination);

            Assert.Equal(2, result.EvidenceFileCount);
            Assert.True(result.PackageBytes > 0);
            using (var archive = ZipFile.OpenRead(destination))
            {
                var names = archive.Entries.Select(entry => entry.FullName).ToArray();
                Assert.Contains("项目证据清单.json", names);
                Assert.Contains("证据包说明.txt", names);
                Assert.Contains("evidence/设备甲/原始输出.txt", names);
                Assert.Contains("evidence/设备甲/证据_001.png", names);
                Assert.DoesNotContain(names, name => name.IndexOf(":", StringComparison.Ordinal) >= 0);
                Assert.Equal("raw-output", ReadEntry(archive, "evidence/设备甲/原始输出.txt"));
                Assert.Equal("image-bytes", ReadEntry(archive, "evidence/设备甲/证据_001.png"));
                Assert.Contains("schemaVersion", ReadEntry(archive, "项目证据清单.json"), StringComparison.Ordinal);
                Assert.Contains("不等同于第三方数字签名", ReadEntry(archive, "证据包说明.txt"), StringComparison.Ordinal);
            }
        }
    }

    [Theory]
    [InlineData(EvidenceShaStatus.Missing)]
    [InlineData(EvidenceShaStatus.Mismatch)]
    [InlineData(EvidenceShaStatus.UnsafePath)]
    [InlineData(EvidenceShaStatus.Unavailable)]
    public async Task Export_blocks_any_unverified_evidence(EvidenceShaStatus status)
    {
        using (var fixture = new PackageFixture())
        {
            var destination = Path.Combine(fixture.ExportDirectory, "blocked.zip");

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                fixture.CreateExporter(status).ExportAsync(fixture.Project, destination));

            Assert.False(File.Exists(destination));
            Assert.Empty(Directory.GetFiles(fixture.ExportDirectory));
        }
    }

    [Fact]
    public async Task Export_rehashes_during_copy_and_removes_temporary_files_on_change()
    {
        using (var fixture = new PackageFixture())
        {
            var exporter = fixture.CreateExporter(EvidenceShaStatus.Verified);
            File.WriteAllText(fixture.RawPath, "changed-after-verification", new UTF8Encoding(false));
            var destination = Path.Combine(fixture.ExportDirectory, "changed.zip");

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                exporter.ExportAsync(fixture.Project, destination));

            Assert.False(File.Exists(destination));
            Assert.Empty(Directory.GetFiles(fixture.ExportDirectory));
        }
    }

    private static string ReadEntry(ZipArchive archive, string name)
    {
        var entry = archive.GetEntry(name) ?? throw new InvalidDataException("ZIP entry is missing: " + name);
        using (var reader = new StreamReader(entry.Open(), Encoding.UTF8))
        {
            return reader.ReadToEnd();
        }
    }

    private sealed class PackageFixture : IDisposable
    {
        private readonly string root;
        private readonly string rawRelative = @"设备甲\原始输出.txt";
        private readonly string imageRelative = @"设备甲\证据_001.png";

        internal PackageFixture()
        {
            root = Path.Combine(Path.GetTempPath(), "EvaluationTool-package-" + Guid.NewGuid().ToString("N"));
            EvidenceRoot = Path.Combine(root, "evidence");
            ExportDirectory = Path.Combine(root, "exports");
            Directory.CreateDirectory(Path.Combine(EvidenceRoot, "设备甲"));
            Directory.CreateDirectory(ExportDirectory);
            RawPath = Path.Combine(EvidenceRoot, "设备甲", "原始输出.txt");
            var imagePath = Path.Combine(EvidenceRoot, "设备甲", "证据_001.png");
            File.WriteAllText(RawPath, "raw-output", new UTF8Encoding(false));
            File.WriteAllText(imagePath, "image-bytes", new UTF8Encoding(false));
            var rawHash = ComputeSha256(RawPath);
            var imageHash = ComputeSha256(imagePath);
            Project = new ProjectRecord(ProjectId.New(), "客户甲", "项目甲", EvidenceRoot, DateTimeOffset.UtcNow);
            var deviceId = DeviceId.New();
            Execution = new ExecutionRecord(
                Project.Id.ToString(),
                deviceId.ToString(),
                ConnectionProtocol.Ssh,
                "generic-linux@1.0.0",
                "linux.identity",
                "id",
                DateTimeOffset.Parse("2026-07-17T09:00:00Z"),
                DateTimeOffset.Parse("2026-07-17T09:00:01Z"),
                ExecutionStatus.Succeeded,
                0,
                rawRelative,
                rawHash,
                new[] { imageRelative },
                new Dictionary<string, string> { [imageRelative] = imageHash },
                null);
            EvidenceFiles = new[]
            {
                new EvidenceFileRecord(Project.Id, deviceId, rawRelative, rawHash,
                    EvidenceFileKind.RawOutput, 0, Execution.StartedAt),
                new EvidenceFileRecord(Project.Id, deviceId, imageRelative, imageHash,
                    EvidenceFileKind.EvidenceImage, 1, Execution.StartedAt)
            };
        }

        internal ProjectRecord Project { get; }
        internal ExecutionRecord Execution { get; }
        internal IReadOnlyList<EvidenceFileRecord> EvidenceFiles { get; }
        internal string EvidenceRoot { get; }
        internal string ExportDirectory { get; }
        internal string RawPath { get; }

        internal ProjectEvidencePackageExporter CreateExporter(EvidenceShaStatus status)
        {
            var item = new EvidenceCenterItem(
                Execution.DeviceId,
                "设备甲",
                Execution.CommandId,
                Execution.CommandText,
                Execution.StartedAt,
                Execution.CompletedAt,
                Execution.Status,
                rawRelative,
                new[] { imageRelative },
                1,
                status);
            var snapshot = new EvidenceCenterSnapshot(Project.Id, new[] { item });
            return new ProjectEvidencePackageExporter(new FakeDocumentProvider(
                new ProjectEvidenceManifestDocument(
                    Project,
                    new[] { Execution },
                    EvidenceFiles,
                    snapshot,
                    new JObject
                    {
                        ["schemaVersion"] = 1,
                        ["projectId"] = Project.Id.ToString()
                    },
                    0)));
        }

        public void Dispose()
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }

        private static string ComputeSha256(string path)
        {
            using (var stream = File.OpenRead(path))
            using (var sha256 = SHA256.Create())
            {
                return string.Concat(sha256.ComputeHash(stream)
                    .Select(value => value.ToString("x2", CultureInfo.InvariantCulture)));
            }
        }
    }

    private sealed class FakeDocumentProvider : IProjectEvidenceManifestDocumentProvider
    {
        private readonly ProjectEvidenceManifestDocument document;

        internal FakeDocumentProvider(ProjectEvidenceManifestDocument document)
        {
            this.document = document;
        }

        public Task<ProjectEvidenceManifestDocument> CreateDocumentAsync(
            ProjectRecord project,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(document);
        }
    }
}
