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
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.App.Services;

public interface IProjectEvidencePackageExporter
{
    Task<EvidencePackageExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default);
}

public interface IEvidencePackageExportFilePicker
{
    string? SelectDestination(ProjectRecord project);
}

public sealed class EvidencePackageExportResult
{
    public EvidencePackageExportResult(string path, int evidenceFileCount, long packageBytes)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
        EvidenceFileCount = evidenceFileCount;
        PackageBytes = packageBytes;
    }

    public string Path { get; }
    public int EvidenceFileCount { get; }
    public long PackageBytes { get; }
    public string Summary => "已打包 " + EvidenceFileCount + " 个已验证证据文件，ZIP 大小 "
        + FormatBytes(PackageBytes) + "。";

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return bytes + " B";
        }

        if (bytes < 1024L * 1024L)
        {
            return (bytes / 1024d).ToString("0.0", CultureInfo.InvariantCulture) + " KB";
        }

        return (bytes / (1024d * 1024d)).ToString("0.0", CultureInfo.InvariantCulture) + " MB";
    }
}

public sealed class ZipEvidencePackageExportFilePicker : IEvidencePackageExportFilePicker
{
    public string? SelectDestination(ProjectRecord project)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        var dialog = new SaveFileDialog
        {
            Title = "导出已验证项目证据包",
            Filter = "ZIP 证据包 (*.zip)|*.zip",
            AddExtension = true,
            DefaultExt = ".zip",
            FileName = SafeFileName(project.ProjectName)
                + "-证据包-" + DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
                + ".zip",
            CheckPathExists = true,
            OverwritePrompt = false
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string SafeFileName(string value)
    {
        var invalid = new HashSet<char>(Path.GetInvalidFileNameChars());
        var normalized = new string(value.Select(character => invalid.Contains(character) ? '_' : character).ToArray())
            .Trim(' ', '.');
        return string.IsNullOrWhiteSpace(normalized) ? "EvaluationTool" : normalized;
    }
}

public sealed class ProjectEvidencePackageExporter : IProjectEvidencePackageExporter
{
    private const string ManifestEntryName = "项目证据清单.json";
    private const string ReadmeEntryName = "证据包说明.txt";
    private readonly IProjectEvidenceManifestDocumentProvider documentProvider;

    public ProjectEvidencePackageExporter(IProjectRepository repository)
        : this(new ProjectEvidenceManifestExporter(repository))
    {
    }

    internal ProjectEvidencePackageExporter(
        IProjectEvidenceManifestDocumentProvider documentProvider)
    {
        this.documentProvider = documentProvider ?? throw new ArgumentNullException(nameof(documentProvider));
    }

    public async Task<EvidencePackageExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        var targetPath = LocalExportDestinationPolicy.ValidateNewFile(
            destinationPath,
            ".zip",
            nameof(destinationPath));
        var plan = await documentProvider.CreateDocumentAsync(project, cancellationToken)
            .ConfigureAwait(false);
        if (!plan.Project.Id.Equals(project.Id)
            || !plan.VerifiedSnapshot.ProjectId.Equals(project.Id))
        {
            throw new InvalidDataException("证据包导出计划属于其他项目。");
        }

        ValidateVerifiedSnapshot(project.Id, plan.Executions, plan.VerifiedSnapshot);
        var packageFiles = ValidateEvidenceIndex(project.Id, plan.Executions, plan.EvidenceFiles);

        var nonce = Guid.NewGuid().ToString("N");
        var temporaryPackagePath = targetPath + "." + nonce + ".tmp";
        try
        {
            WritePackage(
                plan.Project.EvidenceRoot,
                packageFiles,
                plan.Document,
                temporaryPackagePath,
                cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            LocalExportDestinationPolicy.RevalidateNewFile(targetPath);
            File.Move(temporaryPackagePath, targetPath);
            return new EvidencePackageExportResult(
                targetPath,
                packageFiles.Count,
                new FileInfo(targetPath).Length);
        }
        finally
        {
            TryDelete(temporaryPackagePath);
        }
    }

    private static void ValidateVerifiedSnapshot(
        ProjectId projectId,
        IReadOnlyList<ExecutionRecord> executions,
        EvidenceCenterSnapshot snapshot)
    {
        if (!snapshot.ProjectId.Equals(projectId) || snapshot.Items.Count != executions.Count)
        {
            throw new InvalidDataException("执行记录与证据文件复核结果不一致。");
        }

        var executionsByKey = executions.ToDictionary(
            execution => CreateExecutionKey(execution.DeviceId, execution.CommandId, execution.StartedAt));
        var snapshotByKey = snapshot.Items.ToDictionary(
            item => CreateExecutionKey(item.DeviceId, item.CommandId, item.StartedAt));
        if (executionsByKey.Count != snapshotByKey.Count
            || executionsByKey.Keys.Any(key => !snapshotByKey.ContainsKey(key)))
        {
            throw new InvalidDataException("执行记录与证据复核项目不一致。");
        }

        var blockingItems = snapshot.Items
            .Where(item => item.ShaStatus != EvidenceShaStatus.Verified
                && (item.ShaStatus != EvidenceShaStatus.NotAvailable
                    || HasExpectedEvidence(executionsByKey[CreateExecutionKey(
                        item.DeviceId,
                        item.CommandId,
                        item.StartedAt)])))
            .ToArray();
        if (blockingItems.Length != 0)
        {
            throw new InvalidDataException(
                "存在 " + blockingItems.Length + " 条缺失、不一致或不可安全读取的证据，已阻止打包。");
        }
    }

    private static bool HasExpectedEvidence(ExecutionRecord execution)
    {
        return execution.RawOutputPath != null || execution.EvidenceImagePaths.Count != 0;
    }

    private static string CreateExecutionKey(string deviceId, string commandId, DateTimeOffset startedAt)
    {
        return deviceId + "\n" + commandId + "\n"
            + startedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    }

    private static IReadOnlyList<PackageEvidenceFile> ValidateEvidenceIndex(
        ProjectId projectId,
        IReadOnlyList<ExecutionRecord> executions,
        IReadOnlyList<EvidenceFileRecord> evidenceFiles)
    {
        var expected = new Dictionary<string, PackageEvidenceFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var execution in executions)
        {
            if (!string.Equals(execution.ProjectId, projectId.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("执行记录属于其他项目。");
            }

            if (execution.RawOutputPath != null && execution.RawOutputSha256 != null)
            {
                AddExpected(
                    expected,
                    execution.DeviceId,
                    execution.RawOutputPath,
                    execution.RawOutputSha256,
                    EvidenceFileKind.RawOutput);
            }

            foreach (var imagePath in execution.EvidenceImagePaths)
            {
                AddExpected(
                    expected,
                    execution.DeviceId,
                    imagePath,
                    execution.EvidenceImageSha256s[imagePath],
                    EvidenceFileKind.EvidenceImage);
            }
        }

        var indexed = new Dictionary<string, EvidenceFileRecord>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in evidenceFiles)
        {
            if (file == null || !file.ProjectId.Equals(projectId))
            {
                throw new InvalidDataException("证据索引包含其他项目或空记录。");
            }

            var key = CreateEvidenceKey(file.DeviceId.ToString(), file.RelativePath);
            if (indexed.ContainsKey(key)
                || !expected.TryGetValue(key, out var expectedFile)
                || expectedFile.Kind != file.Kind
                || !string.Equals(expectedFile.Sha256, file.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("证据索引包含重复、孤立或哈希冲突记录。");
            }

            indexed.Add(key, file);
        }

        if (indexed.Count != expected.Count)
        {
            throw new InvalidDataException("执行记录与证据文件索引数量不一致。");
        }

        if (expected.Count == 0)
        {
            throw new InvalidDataException("当前项目没有可打包的已验证证据文件。");
        }

        return expected.Values
            .OrderBy(file => file.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(file => file.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void AddExpected(
        IDictionary<string, PackageEvidenceFile> files,
        string deviceId,
        string relativePath,
        string sha256,
        EvidenceFileKind kind)
    {
        var normalizedPath = WindowsEvidenceRelativePathPolicy.Normalize(relativePath, nameof(relativePath));
        var key = CreateEvidenceKey(deviceId, normalizedPath);
        if (files.ContainsKey(key))
        {
            throw new InvalidDataException("多个执行记录引用了同一证据文件。");
        }

        files.Add(key, new PackageEvidenceFile(deviceId, normalizedPath, sha256, kind));
    }

    private static string CreateEvidenceKey(string deviceId, string relativePath)
    {
        return deviceId + "\n" + WindowsEvidenceRelativePathPolicy.Normalize(relativePath, nameof(relativePath));
    }

    private static void WritePackage(
        string evidenceRoot,
        IReadOnlyList<PackageEvidenceFile> files,
        JObject manifest,
        string packagePath,
        CancellationToken cancellationToken)
    {
        var entryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ManifestEntryName,
            ReadmeEntryName
        };
        using (var stream = new FileStream(
            packagePath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            64 * 1024,
            FileOptions.WriteThrough))
        {
            using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
            {
                AddManifest(archive, manifest);
                AddReadme(archive);
                foreach (var file in files)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var entryName = CreateEntryName(file.RelativePath);
                    if (!entryNames.Add(entryName))
                    {
                        throw new InvalidDataException("证据包中出现重复文件路径。");
                    }

                    var entry = archive.CreateEntry(entryName, CompressionLevel.Fastest);
                    using (var source = EvidencePathAccessPolicy.OpenVerifiedFile(
                        evidenceRoot,
                        file.RelativePath))
                    using (var destination = entry.Open())
                    {
                        var actualSha256 = CopyAndHash(source, destination, cancellationToken);
                        if (!string.Equals(actualSha256, file.Sha256, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new InvalidDataException("证据文件在打包过程中发生变化，已阻止生成证据包。");
                        }
                    }
                }
            }

            stream.Flush(true);
        }
    }

    internal static string CreateEntryName(string relativePath)
    {
        var normalized = WindowsEvidenceRelativePathPolicy.Normalize(
            relativePath,
            nameof(relativePath));
        return "evidence/" + normalized.Normalize(NormalizationForm.FormC).Replace('\\', '/');
    }

    private static void AddManifest(ZipArchive archive, JObject manifest)
    {
        var entry = archive.CreateEntry(ManifestEntryName, CompressionLevel.Fastest);
        using (var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false)))
        {
            writer.Write(manifest.ToString(Formatting.Indented));
        }
    }

    private static void AddReadme(ZipArchive archive)
    {
        var entry = archive.CreateEntry(ReadmeEntryName, CompressionLevel.Fastest);
        using (var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false)))
        {
            writer.Write(
                "EvaluationTool 已验证项目证据包\r\n\r\n"
                + "本包由用户在本机明确导出。打包前及复制过程中均按本地 SQLite 索引复核 SHA-256。\r\n"
                + "项目证据清单.json 包含执行、相对路径、哈希和人工确认审计，不包含密码、私钥或原始输出正文。\r\n"
                + "evidence 目录保存实际证据文件。此 ZIP 不等同于第三方数字签名或不可否认性证明。\r\n");
        }
    }

    private static string CopyAndHash(
        Stream source,
        Stream destination,
        CancellationToken cancellationToken)
    {
        using (var sha256 = SHA256.Create())
        {
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                sha256.TransformBlock(buffer, 0, read, buffer, 0);
                destination.Write(buffer, 0, read);
            }

            sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return string.Concat(sha256.Hash!.Select(value => value.ToString("x2", CultureInfo.InvariantCulture)));
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private sealed class PackageEvidenceFile
    {
        internal PackageEvidenceFile(
            string deviceId,
            string relativePath,
            string sha256,
            EvidenceFileKind kind)
        {
            DeviceId = deviceId;
            RelativePath = relativePath;
            Sha256 = sha256;
            Kind = kind;
        }

        internal string DeviceId { get; }
        internal string RelativePath { get; }
        internal string Sha256 { get; }
        internal EvidenceFileKind Kind { get; }
    }
}

internal sealed class UnavailableEvidencePackageExporter : IProjectEvidencePackageExporter
{
    public Task<EvidencePackageExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException("项目证据包导出服务尚未初始化。");
    }
}

internal sealed class UnavailableEvidencePackageExportFilePicker : IEvidencePackageExportFilePicker
{
    public string? SelectDestination(ProjectRecord project) => null;
}
