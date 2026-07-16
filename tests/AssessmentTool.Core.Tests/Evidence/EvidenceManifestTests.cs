using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Evidence;
using Xunit;

namespace AssessmentTool.Core.Tests.Evidence;

public sealed class EvidenceManifestTests : IDisposable
{
    private static readonly DateTimeOffset StartedAt = new DateTimeOffset(2026, 7, 16, 9, 8, 7, TimeSpan.FromHours(8));
    private const string RawOutput = "设备名称：核心交换机\r\n版本：V1.2.3\r\n";
    private const string ImagePath = "证据_001.png";
    private readonly string temporaryRoot = Path.Combine(Path.GetTempPath(), "assessment-tool-manifest-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void FromExecutionRecord_copies_all_traceability_fields_into_an_immutable_snapshot()
    {
        var imagePaths = new List<string> { ImagePath };
        var imageHashes = new Dictionary<string, string> { [ImagePath] = Hash("image-one") };
        var record = Record(
            ExecutionStatus.Failed,
            RawOutput,
            imagePaths,
            imageHashes,
            errorText: "设备未在超时前返回完整输出");

        var manifest = EvidenceManifest.FromExecutionRecord(record, "Timeout");
        imagePaths[0] = "被修改.png";
        imageHashes[ImagePath] = Hash("tampered-image");

        Assert.Equal("project-1", manifest.ProjectId);
        Assert.Equal("device-1", manifest.DeviceId);
        Assert.Equal(ConnectionProtocol.Ssh, manifest.ConnectionProtocol);
        Assert.Equal("pack-1.2.3", manifest.CommandPackVersion);
        Assert.Equal("cmd-show-version", manifest.CommandId);
        Assert.Equal("show version", manifest.Command);
        Assert.Equal(StartedAt, manifest.StartedAt);
        Assert.Equal(StartedAt.AddSeconds(3), manifest.CompletedAt);
        Assert.Equal(ExecutionStatus.Failed, manifest.Status);
        Assert.Equal(1, manifest.ExitCode);
        Assert.Equal("原始输出.txt", manifest.RawOutputPath);
        Assert.Equal(Hash(RawOutput), manifest.RawOutputSha256);
        Assert.Equal(Hash("image-one"), Assert.Single(manifest.EvidenceImageSha256s).Value);
        Assert.False(
            manifest.EvidenceImageSha256s is IDictionary<string, string> mutableHashes && !mutableHashes.IsReadOnly,
            "清单不应向调用方暴露可修改的哈希字典。");
        Assert.Equal("Timeout", manifest.ErrorCategory);
        Assert.Equal("设备未在超时前返回完整输出", manifest.ErrorText);
        Assert.Null(typeof(EvidenceManifest).GetProperty(nameof(EvidenceManifest.RawOutputSha256))!.SetMethod);
        Assert.Null(typeof(EvidenceManifest).GetProperty(nameof(EvidenceManifest.EvidenceImageSha256s))!.SetMethod);
    }

    [Fact]
    public void WriteToDirectory_writes_exact_raw_output_as_utf8_without_a_bom()
    {
        var batchDirectory = CreateBatchDirectory();
        var manifest = EvidenceManifest.FromExecutionRecord(Record(ExecutionStatus.Failed, RawOutput), "Timeout");

        manifest.WriteToDirectory(batchDirectory, RawOutput);

        var bytes = File.ReadAllBytes(Path.Combine(batchDirectory, "原始输出.txt"));
        Assert.False(bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble));
        Assert.Equal(RawOutput, Encoding.UTF8.GetString(bytes));
        Assert.Equal(Hash(RawOutput), Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
    }

    [Fact]
    public void WriteToDirectory_replaces_existing_files_and_leaves_no_temporary_files()
    {
        var batchDirectory = CreateBatchDirectory();
        var rawOutputPath = Path.Combine(batchDirectory, "原始输出.txt");
        var manifestPath = Path.Combine(batchDirectory, "执行记录.json");
        File.WriteAllText(rawOutputPath, "stale raw output");
        File.WriteAllText(manifestPath, "stale manifest");
        var manifest = EvidenceManifest.FromExecutionRecord(Record(ExecutionStatus.Failed, RawOutput), "Timeout");

        manifest.WriteToDirectory(batchDirectory, RawOutput);

        Assert.Equal(RawOutput, File.ReadAllText(rawOutputPath, Encoding.UTF8));
        using var json = JsonDocument.Parse(File.ReadAllBytes(manifestPath));
        Assert.Equal(Hash(RawOutput), json.RootElement.GetProperty("rawOutputSha256").GetString());
        Assert.DoesNotContain(
            Directory.EnumerateFiles(batchDirectory),
            path => !string.Equals(path, rawOutputPath, StringComparison.Ordinal)
                && !string.Equals(path, manifestPath, StringComparison.Ordinal));
    }

    [Fact]
    public void WriteToDirectory_rejects_changed_raw_output_without_replacing_existing_evidence()
    {
        var batchDirectory = CreateBatchDirectory();
        var rawOutputPath = Path.Combine(batchDirectory, "原始输出.txt");
        var manifestPath = Path.Combine(batchDirectory, "执行记录.json");
        File.WriteAllText(rawOutputPath, "previous raw output");
        File.WriteAllText(manifestPath, "previous manifest");
        var manifest = EvidenceManifest.FromExecutionRecord(Record(ExecutionStatus.Failed, RawOutput), "Timeout");

        Assert.Throws<InvalidDataException>(() => manifest.WriteToDirectory(batchDirectory, RawOutput + "tampered"));

        Assert.Equal("previous raw output", File.ReadAllText(rawOutputPath));
        Assert.Equal("previous manifest", File.ReadAllText(manifestPath));
        Assert.Equal(2, Directory.EnumerateFiles(batchDirectory).Count());
    }

    [Fact]
    public void Written_manifest_contains_exact_execution_fields_and_immutable_artifact_hashes()
    {
        var batchDirectory = CreateBatchDirectory();
        var imageBytes = Encoding.UTF8.GetBytes("image-one");
        File.WriteAllBytes(Path.Combine(batchDirectory, ImagePath), imageBytes);
        var imageHashes = new Dictionary<string, string>
        {
            [ImagePath] = Convert.ToHexString(SHA256.HashData(imageBytes)).ToLowerInvariant()
        };
        var manifest = EvidenceManifest.FromExecutionRecord(
            Record(ExecutionStatus.Succeeded, RawOutput, new[] { ImagePath }, imageHashes, null),
            null);

        manifest.WriteToDirectory(batchDirectory, RawOutput);
        imageHashes[ImagePath] = Hash("changed-after-write");
        using var json = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(batchDirectory, "执行记录.json")));
        var root = json.RootElement;

        Assert.Equal("pack-1.2.3", root.GetProperty("commandPackVersion").GetString());
        Assert.Equal("show version", root.GetProperty("command").GetString());
        Assert.Equal(StartedAt, root.GetProperty("startedAt").GetDateTimeOffset());
        Assert.Equal(StartedAt.AddSeconds(3), root.GetProperty("completedAt").GetDateTimeOffset());
        Assert.Equal("Succeeded", root.GetProperty("status").GetString());
        Assert.Equal(Hash(RawOutput), root.GetProperty("rawOutputSha256").GetString());
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(imageBytes)).ToLowerInvariant(),
            root.GetProperty("evidenceImageSha256s").GetProperty(ImagePath).GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("errorCategory").ValueKind);
    }

    [Fact]
    public void WriteToDirectory_rejects_raw_output_that_collides_with_the_manifest_name()
    {
        var batchDirectory = CreateBatchDirectory();
        var record = new ExecutionRecord(
            "project-1",
            "device-1",
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            "cmd-show-version",
            "show version",
            StartedAt,
            StartedAt.AddSeconds(3),
            ExecutionStatus.Failed,
            1,
            "执行记录.json",
            Hash(RawOutput),
            Array.Empty<string>(),
            new Dictionary<string, string>(),
            "失败");

        var manifest = EvidenceManifest.FromExecutionRecord(record, "Command");

        Assert.Throws<InvalidDataException>(() => manifest.WriteToDirectory(batchDirectory, RawOutput));
        Assert.Empty(Directory.EnumerateFiles(batchDirectory));
    }

    [Fact]
    public void Manifest_json_is_byte_stable_for_different_hash_dictionary_insertion_orders()
    {
        var firstDirectory = CreateBatchDirectory();
        var secondDirectory = CreateBatchDirectory();
        var paths = new[] { "证据_001.png", "证据_002.png" };
        foreach (var directory in new[] { firstDirectory, secondDirectory })
        {
            File.WriteAllText(Path.Combine(directory, paths[0]), "image-one");
            File.WriteAllText(Path.Combine(directory, paths[1]), "image-two");
        }

        var firstHashes = new Dictionary<string, string>
        {
            [paths[0]] = Hash("image-one"),
            [paths[1]] = Hash("image-two")
        };
        var secondHashes = new Dictionary<string, string>
        {
            [paths[1]] = Hash("image-two"),
            [paths[0]] = Hash("image-one")
        };
        EvidenceManifest.FromExecutionRecord(
            Record(ExecutionStatus.Succeeded, RawOutput, paths, firstHashes, null),
            null).WriteToDirectory(firstDirectory, RawOutput);
        EvidenceManifest.FromExecutionRecord(
            Record(ExecutionStatus.Succeeded, RawOutput, paths, secondHashes, null),
            null).WriteToDirectory(secondDirectory, RawOutput);

        Assert.Equal(
            File.ReadAllBytes(Path.Combine(firstDirectory, "执行记录.json")),
            File.ReadAllBytes(Path.Combine(secondDirectory, "执行记录.json")));
    }

    public void Dispose()
    {
        if (Directory.Exists(temporaryRoot))
        {
            Directory.Delete(temporaryRoot, true);
        }
    }

    private string CreateBatchDirectory()
    {
        var path = Path.Combine(temporaryRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static ExecutionRecord Record(
        ExecutionStatus status,
        string rawOutput,
        IEnumerable<string>? imagePaths = null,
        IDictionary<string, string>? imageHashes = null,
        string? errorText = "设备未在超时前返回完整输出")
    {
        return new ExecutionRecord(
            "project-1",
            "device-1",
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            "cmd-show-version",
            "show version",
            StartedAt,
            StartedAt.AddSeconds(3),
            status,
            status == ExecutionStatus.Succeeded ? 0 : 1,
            "原始输出.txt",
            Hash(rawOutput),
            imagePaths ?? Array.Empty<string>(),
            imageHashes ?? new Dictionary<string, string>(),
            errorText);
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }
}
