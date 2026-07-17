using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.App.Services;

public interface IEvidenceRecoveryService
{
    Task<EvidenceRecoveryResult> RecoverAsync(
        ProjectRecord project,
        CancellationToken cancellationToken = default);
}

public sealed class EvidenceRecoveryResult
{
    public EvidenceRecoveryResult(int scannedCount, int recoveredCount, int alreadyIndexedCount, int failedCount)
    {
        if (scannedCount < 0 || recoveredCount < 0 || alreadyIndexedCount < 0 || failedCount < 0
            || recoveredCount + alreadyIndexedCount + failedCount != scannedCount)
        {
            throw new ArgumentOutOfRangeException(nameof(scannedCount));
        }

        ScannedCount = scannedCount;
        RecoveredCount = recoveredCount;
        AlreadyIndexedCount = alreadyIndexedCount;
        FailedCount = failedCount;
    }

    public int ScannedCount { get; }
    public int RecoveredCount { get; }
    public int AlreadyIndexedCount { get; }
    public int FailedCount { get; }
    public string Summary => ScannedCount == 0
        ? "未发现待恢复的证据批次。"
        : "已检查 " + ScannedCount + " 个待恢复批次：成功恢复 " + RecoveredCount
          + " 个，已在索引中 " + AlreadyIndexedCount + " 个，仍需人工处理 " + FailedCount + " 个。";
}

public sealed class EvidenceRecoveryService : IEvidenceRecoveryService
{
    private const string MarkerFileName = "待入库.txt";
    private const string ManifestFileName = "执行记录.json";
    private const int MaximumMarkers = 500;
    private const int MaximumDirectories = 10000;
    private const int MaximumManifestBytes = 1024 * 1024;
    private const int MaximumEvidenceImages = 500;
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

    private readonly IProjectRepository repository;
    private readonly EvidenceFileIntegrityVerifier integrityVerifier;

    public EvidenceRecoveryService(IProjectRepository repository)
        : this(repository, new EvidenceFileIntegrityVerifier())
    {
    }

    internal EvidenceRecoveryService(
        IProjectRepository repository,
        EvidenceFileIntegrityVerifier integrityVerifier)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.integrityVerifier = integrityVerifier ?? throw new ArgumentNullException(nameof(integrityVerifier));
    }

    public async Task<EvidenceRecoveryResult> RecoverAsync(
        ProjectRecord project,
        CancellationToken cancellationToken = default)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        var root = NormalizeRoot(project.EvidenceRoot);
        if (!Directory.Exists(root))
        {
            return new EvidenceRecoveryResult(0, 0, 0, 0);
        }

        EnsureNoReparsePoint(root);
        var devices = await repository.GetDevicesAsync(project.Id, cancellationToken).ConfigureAwait(false);
        var executions = await repository.GetExecutionsAsync(project.Id, cancellationToken).ConfigureAwait(false);
        var deviceIds = new HashSet<string>(
            devices.Select(device => device.Id.ToString()),
            StringComparer.OrdinalIgnoreCase);
        var indexed = new HashSet<string>(
            executions.Where(execution => execution.RawOutputPath != null && execution.RawOutputSha256 != null)
                .Select(execution => IndexKey(execution.RawOutputPath!, execution.RawOutputSha256!)),
            StringComparer.OrdinalIgnoreCase);

        var markers = EnumerateMarkers(root, cancellationToken);
        var recovered = 0;
        var alreadyIndexed = 0;
        var failed = 0;
        foreach (var marker in markers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var record = ReadAndVerifyRecord(project, root, marker, deviceIds, cancellationToken);
                var key = IndexKey(
                    record.RawOutputPath ?? throw new InvalidDataException("恢复记录缺少原始输出路径。"),
                    record.RawOutputSha256 ?? throw new InvalidDataException("恢复记录缺少原始输出哈希。"));
                if (indexed.Contains(key))
                {
                    File.Delete(marker);
                    alreadyIndexed++;
                    continue;
                }

                await repository.SaveExecutionAsync(record, CancellationToken.None).ConfigureAwait(false);
                indexed.Add(key);
                File.Delete(marker);
                recovered++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                failed++;
            }
        }

        return new EvidenceRecoveryResult(markers.Count, recovered, alreadyIndexed, failed);
    }

    private ExecutionRecord ReadAndVerifyRecord(
        ProjectRecord project,
        string root,
        string marker,
        ISet<string> deviceIds,
        CancellationToken cancellationToken)
    {
        var batchDirectory = Path.GetDirectoryName(marker)
            ?? throw new InvalidDataException("待恢复标记缺少批次目录。");
        EnsureContained(root, batchDirectory);
        EnsureSafePathChain(root, batchDirectory);
        EnsureNoReparsePoint(marker);
        var manifestPath = Path.Combine(batchDirectory, ManifestFileName);
        EnsureNoReparsePoint(manifestPath);
        var document = ReadManifest(manifestPath);

        RequireInteger(document, "schemaVersion", 1);
        var projectId = RequireString(document, "projectId", 100);
        var deviceId = RequireString(document, "deviceId", 100);
        if (!string.Equals(projectId, project.Id.ToString(), StringComparison.OrdinalIgnoreCase)
            || !deviceIds.Contains(deviceId))
        {
            throw new InvalidDataException("执行清单不属于当前项目设备。");
        }

        var protocol = ParseEnum<ConnectionProtocol>(RequireString(document, "connectionProtocol", 100));
        var status = ParseEnum<ExecutionStatus>(RequireString(document, "status", 100));
        var startedAt = ParseTimestamp(RequireString(document, "startedAt", 100));
        var completedAt = OptionalString(document, "completedAt", 100);
        var rawLocalPath = RequireLocalArtifactPath(document, "rawOutputPath");
        var rawHash = RequireSha256(document, "rawOutputSha256");
        var imageHashes = ReadImageHashes(document);
        var batchRelative = MakeRelative(root, batchDirectory);
        var rawRelative = CombineRelative(batchRelative, rawLocalPath);
        var imageRelativeHashes = imageHashes.ToDictionary(
            item => CombineRelative(batchRelative, item.Key),
            item => item.Value,
            StringComparer.OrdinalIgnoreCase);

        var expectedFiles = new List<ExpectedEvidenceFile>
        {
            new ExpectedEvidenceFile(rawRelative, rawHash)
        };
        expectedFiles.AddRange(imageRelativeHashes.Select(item => new ExpectedEvidenceFile(item.Key, item.Value)));
        if (integrityVerifier.Verify(root, expectedFiles, cancellationToken) != EvidenceShaStatus.Verified)
        {
            throw new InvalidDataException("待恢复证据文件与执行清单不一致。");
        }

        return new ExecutionRecord(
            projectId,
            deviceId,
            protocol,
            RequireString(document, "commandPackVersion", 100),
            RequireString(document, "commandId", 200),
            RequireString(document, "command", 8192),
            startedAt,
            completedAt == null ? (DateTimeOffset?)null : ParseTimestamp(completedAt),
            status,
            OptionalInteger(document, "exitCode"),
            rawRelative,
            rawHash,
            imageRelativeHashes.Keys,
            imageRelativeHashes,
            OptionalString(document, "errorText", 8192));
    }

    private static JObject ReadManifest(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length < 2 || info.Length > MaximumManifestBytes)
        {
            throw new InvalidDataException("执行清单缺失或大小异常。");
        }

        string json;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096))
        using (var reader = new StreamReader(stream, StrictUtf8, false, 4096))
        {
            json = reader.ReadToEnd();
        }

        using (var textReader = new JsonTextReader(new StringReader(json))
        {
            DateParseHandling = DateParseHandling.None,
            MaxDepth = 16
        })
        {
            var token = JToken.Load(textReader, new JsonLoadSettings
            {
                DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error,
                CommentHandling = CommentHandling.Ignore,
                LineInfoHandling = LineInfoHandling.Ignore
            });
            if (token.Type != JTokenType.Object || textReader.Read())
            {
                throw new InvalidDataException("执行清单结构无效。");
            }

            return (JObject)token;
        }
    }

    private static IReadOnlyDictionary<string, string> ReadImageHashes(JObject document)
    {
        var token = document["evidenceImageSha256s"];
        if (token == null || token.Type != JTokenType.Object)
        {
            throw new InvalidDataException("执行清单缺少截图哈希。");
        }

        var properties = ((JObject)token).Properties().ToArray();
        if (properties.Length > MaximumEvidenceImages)
        {
            throw new InvalidDataException("执行清单截图数量超过限制。");
        }

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in properties)
        {
            var path = NormalizeLocalArtifactPath(property.Name);
            if (property.Value.Type != JTokenType.String || result.ContainsKey(path))
            {
                throw new InvalidDataException("执行清单截图哈希无效或重复。");
            }

            result.Add(path, ValidateSha256((string?)property.Value));
        }

        return new ReadOnlyDictionary<string, string>(result);
    }

    private static IReadOnlyList<string> EnumerateMarkers(string root, CancellationToken cancellationToken)
    {
        var markers = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);
        var directoryCount = 0;
        while (pending.Count != 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            if (++directoryCount > MaximumDirectories)
            {
                throw new InvalidDataException("证据目录数量超过安全扫描限制。");
            }

            EnsureSafePathChain(root, directory);
            var marker = Path.Combine(directory, MarkerFileName);
            if (File.Exists(marker))
            {
                if (markers.Count >= MaximumMarkers)
                {
                    throw new InvalidDataException("待恢复证据数量超过单次安全处理限制。");
                }

                markers.Add(marker);
            }

            foreach (var child in Directory.EnumerateDirectories(directory))
            {
                EnsureNoReparsePoint(child);
                pending.Push(child);
            }
        }

        return new ReadOnlyCollection<string>(markers.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static string NormalizeRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("项目证据目录不能为空。", nameof(root));
        }

        var fullPath = Path.GetFullPath(root);
        var pathRoot = Path.GetPathRoot(fullPath);
        return string.Equals(fullPath, pathRoot, StringComparison.OrdinalIgnoreCase)
            ? fullPath
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static void EnsureContained(string root, string path)
    {
        var rootWithSeparator = root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            || root.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? root
                : root + Path.DirectorySeparatorChar;
        var fullPath = Path.GetFullPath(path);
        if (!fullPath.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("待恢复证据路径超出项目目录。");
        }
    }

    private static void EnsureSafePathChain(string root, string path)
    {
        EnsureContained(root, path);
        var relative = Path.GetFullPath(path).Substring(root.Length)
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = root;
        EnsureNoReparsePoint(current);
        foreach (var segment in relative.Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            EnsureNoReparsePoint(current);
        }
    }

    private static void EnsureNoReparsePoint(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path))
            && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("证据路径包含重解析点。");
        }
    }

    private static string MakeRelative(string root, string path)
    {
        EnsureContained(root, path);
        return Path.GetFullPath(path).Substring(root.Length)
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Replace(Path.DirectorySeparatorChar, '\\')
            .Replace(Path.AltDirectorySeparatorChar, '\\');
    }

    private static string CombineRelative(string directory, string fileName)
    {
        return WindowsEvidenceRelativePathPolicy.Normalize(
            string.IsNullOrEmpty(directory) ? fileName : directory + "\\" + fileName,
            nameof(fileName));
    }

    private static string RequireLocalArtifactPath(JObject document, string name)
    {
        return NormalizeLocalArtifactPath(RequireString(document, name, 260));
    }

    private static string NormalizeLocalArtifactPath(string path)
    {
        var normalized = WindowsEvidenceRelativePathPolicy.Normalize(path, nameof(path));
        if (normalized.IndexOf('\\') >= 0)
        {
            throw new InvalidDataException("执行清单只能引用当前批次目录中的文件。");
        }

        return normalized;
    }

    private static string RequireString(JObject document, string name, int maximumLength)
    {
        var token = document[name];
        var value = token?.Type == JTokenType.String ? (string?)token : null;
        if (value == null
            || string.IsNullOrWhiteSpace(value)
            || value.Length > maximumLength
            || value.Any(character => character == '\0'))
        {
            throw new InvalidDataException("执行清单字段无效：" + name);
        }

        return value;
    }

    private static string? OptionalString(JObject document, string name, int maximumLength)
    {
        var token = document[name];
        if (token == null || token.Type == JTokenType.Null)
        {
            return null;
        }

        if (token.Type != JTokenType.String)
        {
            throw new InvalidDataException("执行清单字段类型无效：" + name);
        }

        var value = (string?)token;
        if (value == null || value.Length > maximumLength || value.Any(character => character == '\0'))
        {
            throw new InvalidDataException("执行清单字段无效：" + name);
        }

        return value;
    }

    private static int? OptionalInteger(JObject document, string name)
    {
        var token = document[name];
        if (token == null || token.Type == JTokenType.Null)
        {
            return null;
        }

        if (token.Type != JTokenType.Integer)
        {
            throw new InvalidDataException("执行清单整数字段无效：" + name);
        }

        return checked((int)token.Value<long>());
    }

    private static void RequireInteger(JObject document, string name, int expected)
    {
        if (OptionalInteger(document, name) != expected)
        {
            throw new InvalidDataException("执行清单版本不受支持。");
        }
    }

    private static string RequireSha256(JObject document, string name)
    {
        return ValidateSha256(RequireString(document, name, 64));
    }

    private static string ValidateSha256(string? value)
    {
        if (value == null || value.Length != 64 || value.Any(character =>
                !((character >= '0' && character <= '9')
                  || (character >= 'a' && character <= 'f')
                  || (character >= 'A' && character <= 'F'))))
        {
            throw new InvalidDataException("执行清单 SHA-256 无效。");
        }

        return value.ToLowerInvariant();
    }

    private static TEnum ParseEnum<TEnum>(string value)
        where TEnum : struct
    {
        if (!Enum.TryParse(value, false, out TEnum parsed) || !Enum.IsDefined(typeof(TEnum), parsed))
        {
            throw new InvalidDataException("执行清单枚举字段无效。");
        }

        return parsed;
    }

    private static DateTimeOffset ParseTimestamp(string value)
    {
        if (!DateTimeOffset.TryParseExact(
                value,
                "o",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var parsed))
        {
            throw new InvalidDataException("执行清单时间字段无效。");
        }

        return parsed;
    }

    private static string IndexKey(string relativePath, string sha256)
    {
        return WindowsEvidenceRelativePathPolicy.Normalize(relativePath, nameof(relativePath))
               + "|" + ValidateSha256(sha256);
    }
}
