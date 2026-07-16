using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AssessmentTool.Core.Domain;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.Core.Evidence;

public sealed class EvidenceManifest
{
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

    private EvidenceManifest(ExecutionRecord record, string? errorCategory)
    {
        ProjectId = record.ProjectId;
        DeviceId = record.DeviceId;
        ConnectionProtocol = record.ConnectionProtocol;
        CommandPackVersion = record.CommandPackVersion;
        CommandId = record.CommandId;
        Command = record.CommandText;
        StartedAt = record.StartedAt;
        CompletedAt = record.CompletedAt;
        Status = record.Status;
        ExitCode = record.ExitCode;
        RawOutputPath = record.RawOutputPath;
        RawOutputSha256 = record.RawOutputSha256;
        EvidenceImageSha256s = new ReadOnlyDictionary<string, string>(
            record.EvidenceImageSha256s.ToDictionary(
                item => item.Key,
                item => item.Value,
                StringComparer.OrdinalIgnoreCase));
        ErrorCategory = errorCategory;
        ErrorText = record.ErrorText;
    }

    public string ProjectId { get; }
    public string DeviceId { get; }
    public ConnectionProtocol ConnectionProtocol { get; }
    public string CommandPackVersion { get; }
    public string CommandId { get; }
    public string Command { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset? CompletedAt { get; }
    public ExecutionStatus Status { get; }
    public int? ExitCode { get; }
    public string? RawOutputPath { get; }
    public string? RawOutputSha256 { get; }
    public IReadOnlyDictionary<string, string> EvidenceImageSha256s { get; }
    public string? ErrorCategory { get; }
    public string? ErrorText { get; }

    public static EvidenceManifest FromExecutionRecord(ExecutionRecord record, string? errorCategory)
    {
        if (record == null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        return new EvidenceManifest(record, errorCategory);
    }

    public void WriteToDirectory(string batchDirectory, string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(batchDirectory))
        {
            throw new ArgumentException("证据批次目录不能为空。", nameof(batchDirectory));
        }

        if (rawOutput == null)
        {
            throw new ArgumentNullException(nameof(rawOutput));
        }

        if (!Directory.Exists(batchDirectory))
        {
            throw new DirectoryNotFoundException("证据批次目录不存在。" + batchDirectory);
        }

        EnsureNotReparsePoint(Path.GetFullPath(batchDirectory));
        ValidateArtifactPaths();

        var rawBytes = StrictUtf8.GetBytes(rawOutput);
        var actualRawHash = ComputeSha256(rawBytes);
        if (RawOutputPath == null
            || RawOutputSha256 == null
            || !string.Equals(actualRawHash, RawOutputSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("原始输出与执行记录中的 SHA-256 不一致，已阻止覆盖证据。");
        }

        var imageEntries = EvidenceImageSha256s.ToArray();
        var lockedImages = new List<FileStream>();
        try
        {
            foreach (var image in imageEntries)
            {
                var imagePath = ResolveChildPath(batchDirectory, image.Key);
                EnsureNoReparsePoints(batchDirectory, image.Key);
                var stream = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                lockedImages.Add(stream);
                if (!string.Equals(ComputeSha256(stream), image.Value, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("证据图片与执行记录中的 SHA-256 不一致。");
                }
            }

            var rawPath = ResolveChildPath(batchDirectory, RawOutputPath);
            var manifestPath = ResolveChildPath(batchDirectory, "执行记录.json");
            EnsureNoReparsePoints(batchDirectory, RawOutputPath);
            EnsureNoReparsePoints(batchDirectory, "执行记录.json");
            WriteAtomically(rawPath, rawBytes);
            using (var lockedRaw = new FileStream(rawPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (!string.Equals(ComputeSha256(lockedRaw), actualRawHash, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("原始输出在提交清单前发生变化。");
                }

                for (var index = 0; index < lockedImages.Count; index++)
                {
                    lockedImages[index].Position = 0;
                    if (!string.Equals(
                        ComputeSha256(lockedImages[index]),
                        imageEntries[index].Value,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("证据图片在提交清单前发生变化。");
                    }
                }

                WriteAtomically(manifestPath, BuildJson(actualRawHash));
            }
        }
        finally
        {
            foreach (var image in lockedImages)
            {
                image.Dispose();
            }
        }
    }

    private byte[] BuildJson(string actualRawHash)
    {
        var imageHashes = new JObject();
        foreach (var image in EvidenceImageSha256s.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            imageHashes.Add(image.Key, image.Value.ToLowerInvariant());
        }

        var document = new JObject
        {
            ["schemaVersion"] = 1,
            ["projectId"] = ProjectId,
            ["deviceId"] = DeviceId,
            ["connectionProtocol"] = ConnectionProtocol.ToString(),
            ["commandPackVersion"] = CommandPackVersion,
            ["commandId"] = CommandId,
            ["command"] = Command,
            ["startedAt"] = StartedAt.ToString("o", CultureInfo.InvariantCulture),
            ["completedAt"] = CompletedAt.HasValue
                ? new JValue(CompletedAt.Value.ToString("o", CultureInfo.InvariantCulture))
                : JValue.CreateNull(),
            ["status"] = Status.ToString(),
            ["exitCode"] = ExitCode.HasValue ? new JValue(ExitCode.Value) : JValue.CreateNull(),
            ["rawOutputPath"] = RawOutputPath,
            ["rawOutputSha256"] = actualRawHash,
            ["evidenceImageSha256s"] = imageHashes,
            ["errorCategory"] = ErrorCategory == null ? JValue.CreateNull() : new JValue(ErrorCategory),
            ["errorText"] = ErrorText == null ? JValue.CreateNull() : new JValue(ErrorText)
        };
        var json = document.ToString(Formatting.Indented).Replace("\r\n", "\n") + "\n";
        return StrictUtf8.GetBytes(json);
    }

    private void ValidateArtifactPaths()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "执行记录.json" };
        if (RawOutputPath == null || !paths.Add(RawOutputPath))
        {
            throw new InvalidDataException("原始输出路径与证据清单路径冲突。");
        }

        foreach (var imagePath in EvidenceImageSha256s.Keys)
        {
            if (!paths.Add(imagePath))
            {
                throw new InvalidDataException("证据文件路径之间存在冲突。");
            }
        }
    }

    private static string ResolveChildPath(string batchDirectory, string relativePath)
    {
        var normalized = WindowsEvidenceRelativePathPolicy.Normalize(relativePath, nameof(relativePath));
        var root = Path.GetFullPath(batchDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var absolute = Path.GetFullPath(Path.Combine(root, normalized.Replace('\\', Path.DirectorySeparatorChar)));
        if (!absolute.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("证据文件路径超出当前批次目录。");
        }

        return absolute;
    }

    private static void EnsureNotReparsePoint(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return;
        }

        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("证据路径包含符号链接或 Windows 重解析点，已阻止写入。");
        }
    }

    private static void EnsureNoReparsePoints(string batchDirectory, string relativePath)
    {
        var current = Path.GetFullPath(batchDirectory);
        EnsureNotReparsePoint(current);
        var normalized = WindowsEvidenceRelativePathPolicy.Normalize(relativePath, nameof(relativePath));
        foreach (var segment in normalized.Split('\\'))
        {
            current = Path.Combine(current, segment);
            EnsureNotReparsePoint(current);
        }
    }

    private static void WriteAtomically(string targetPath, byte[] content)
    {
        var temporaryPath = targetPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(content, 0, content.Length);
                stream.Flush(true);
            }

            if (File.Exists(targetPath))
            {
                File.Replace(temporaryPath, targetPath, null);
            }
            else
            {
                File.Move(temporaryPath, targetPath);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static string ComputeSha256(Stream stream)
    {
        using (var sha256 = SHA256.Create())
        {
            return ToLowerHex(sha256.ComputeHash(stream));
        }
    }

    private static string ComputeSha256(byte[] bytes)
    {
        using (var sha256 = SHA256.Create())
        {
            return ToLowerHex(sha256.ComputeHash(bytes));
        }
    }

    private static string ToLowerHex(IEnumerable<byte> bytes)
    {
        return string.Concat(bytes.Select(value => value.ToString("x2", CultureInfo.InvariantCulture)));
    }
}
