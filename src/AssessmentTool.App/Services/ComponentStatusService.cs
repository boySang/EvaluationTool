using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AssessmentTool.Windows.Components;

namespace AssessmentTool.App.Services;

public sealed class ComponentStatusService : IComponentStatusService
{
    private const long MaximumPlinkBytes = 4L * 1024 * 1024;
    private readonly string applicationRoot;
    private readonly ComponentDefinition definition;
    private readonly Func<ComponentStatus> inspectInstalled;

    public ComponentStatusService()
        : this(AppDomain.CurrentDomain.BaseDirectory)
    {
    }

    internal ComponentStatusService(string applicationRoot)
        : this(
            applicationRoot,
            TrustedComponentCatalog.Plink,
            () => new ComponentInspector(applicationRoot).Inspect(TrustedComponentCatalog.Plink))
    {
    }

    internal ComponentStatusService(
        string applicationRoot,
        ComponentDefinition definition,
        Func<ComponentStatus> inspectInstalled)
    {
        if (string.IsNullOrWhiteSpace(applicationRoot))
        {
            throw new ArgumentException("程序目录不能为空。", nameof(applicationRoot));
        }

        this.applicationRoot = Path.GetFullPath(applicationRoot);
        this.definition = definition ?? throw new ArgumentNullException(nameof(definition));
        this.inspectInstalled = inspectInstalled ?? throw new ArgumentNullException(nameof(inspectInstalled));
    }

    public Task<ComponentStatus> GetPlinkStatusAsync()
    {
        return Task.Run(() =>
            inspectInstalled());
    }

    public Task<ComponentInstallPreview> PreparePlinkInstallAsync(string sourcePath)
    {
        return Task.Run(() => InspectSource(sourcePath));
    }

    public Task<ComponentStatus> InstallPreparedPlinkAsync(ComponentInstallPreview preview)
    {
        if (preview == null)
        {
            throw new ArgumentNullException(nameof(preview));
        }

        return Task.Run(() => Install(preview));
    }

    private ComponentInstallPreview InspectSource(string sourcePath)
    {
        var fullPath = ValidateLocalSourcePath(sourcePath);
        var installedPath = Path.GetFullPath(Path.Combine(applicationRoot, definition.TrustedRelativePath));
        if (string.Equals(fullPath, installedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("请选择另一份离线 Plink 文件，不能把当前安装目标作为来源。");
        }

        using (var stream = OpenLockedSource(fullPath))
        {
            var length = stream.Length;
            if (length <= 0 || length > MaximumPlinkBytes)
            {
                throw new InvalidDataException("Plink 离线组件大小必须大于 0 且不超过 4 MB。");
            }

            var hash = ComputeSha256(stream);
            if (!string.Equals(
                hash,
                definition.ExpectedSha256,
                StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("所选文件不是当前版本信任的官方 Plink 0.84 x64 组件。");
            }

            return new ComponentInstallPreview(
                fullPath,
                Path.GetFileName(fullPath),
                length,
                hash);
        }
    }

    private ComponentStatus Install(ComponentInstallPreview preview)
    {
        var sourcePath = ValidateLocalSourcePath(preview.SourcePath);
        var targetPath = Path.GetFullPath(Path.Combine(applicationRoot, definition.TrustedRelativePath));
        EnsureWithinApplicationRoot(targetPath);
        var targetDirectory = Path.GetDirectoryName(targetPath)
            ?? throw new InvalidOperationException("无法解析组件安装目录。");
        Directory.CreateDirectory(targetDirectory);
        EnsureOrdinaryDirectoryChain(applicationRoot);
        EnsureOrdinaryDirectoryChain(targetDirectory);

        var temporaryPath = Path.Combine(targetDirectory, ".plink-install-" + Guid.NewGuid().ToString("N") + ".tmp");
        var backupPath = Path.Combine(targetDirectory, ".plink-backup-" + Guid.NewGuid().ToString("N") + ".bak");
        var hadExistingTarget = File.Exists(targetPath);
        var replacementStarted = false;
        var preserveBackup = false;
        try
        {
            using (var source = OpenLockedSource(sourcePath))
            {
                if (source.Length != preview.SizeBytes)
                {
                    throw new InvalidDataException("离线组件在确认后发生变化，已停止安装。");
                }

                var currentHash = ComputeSha256(source);
                if (!string.Equals(currentHash, preview.Sha256, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(currentHash, definition.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("离线组件在确认后发生变化或哈希不受信任，已停止安装。");
                }

                source.Position = 0;
                using (var destination = new FileStream(
                    temporaryPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    81920,
                    FileOptions.WriteThrough))
                {
                    source.CopyTo(destination);
                    destination.Flush(true);
                }
            }

            using (var staged = new FileStream(
                temporaryPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                81920,
                FileOptions.SequentialScan))
            {
                if (!string.Equals(
                    ComputeSha256(staged),
                    definition.ExpectedSha256,
                    StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("安装暂存文件完整性校验失败。");
                }
            }

            replacementStarted = true;
            if (hadExistingTarget)
            {
                File.Replace(temporaryPath, targetPath, backupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, targetPath);
            }

            var status = inspectInstalled();
            if (!status.Available)
            {
                throw new InvalidDataException("组件安装后未通过版本、架构和文件身份复核。");
            }

            TryDelete(backupPath);
            return status;
        }
        catch
        {
            if (replacementStarted)
            {
                try
                {
                    TryRollback(targetPath, backupPath, hadExistingTarget);
                }
                catch
                {
                    preserveBackup = true;
                    throw;
                }
            }

            throw;
        }
        finally
        {
            TryDelete(temporaryPath);
            if (!preserveBackup)
            {
                TryDelete(backupPath);
            }
        }
    }

    private static string ValidateLocalSourcePath(string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath)
            || sourcePath.StartsWith(@"\\", StringComparison.Ordinal)
            || sourcePath.StartsWith(@"\\?\", StringComparison.Ordinal)
            || !Path.IsPathRooted(sourcePath))
        {
            throw new ArgumentException("离线组件必须是本机磁盘上的完整路径。", nameof(sourcePath));
        }

        var fullPath = Path.GetFullPath(sourcePath);
        if (!File.Exists(fullPath)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("离线组件不存在或使用了不安全的重解析路径。");
        }

        EnsureOrdinaryDirectoryChain(Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("离线组件目录无效。"));
        return fullPath;
    }

    private void EnsureWithinApplicationRoot(string path)
    {
        var root = applicationRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var prefix = root + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("组件安装路径超出程序目录。");
        }
    }

    private static void EnsureOrdinaryDirectoryChain(string path)
    {
        DirectoryInfo? current = new DirectoryInfo(path);
        while (current != null)
        {
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("组件来源路径包含不存在或不安全的重解析目录。");
            }

            current = current.Parent;
        }
    }

    private static FileStream OpenLockedSource(string path)
    {
        return new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            FileOptions.SequentialScan);
    }

    private static string ComputeSha256(Stream stream)
    {
        stream.Position = 0;
        using (var algorithm = SHA256.Create())
        {
            return BitConverter.ToString(algorithm.ComputeHash(stream))
                .Replace("-", string.Empty)
                .ToLowerInvariant();
        }
    }

    private static void TryRollback(string targetPath, string backupPath, bool hadExistingTarget)
    {
        try
        {
            if (hadExistingTarget && File.Exists(backupPath))
            {
                if (File.Exists(targetPath))
                {
                    File.Replace(backupPath, targetPath, null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(backupPath, targetPath);
                }
            }
            else if (!hadExistingTarget)
            {
                TryDelete(targetPath);
            }
        }
        catch
        {
            throw new IOException("组件安装失败且自动回滚未完成，请重新解压完整软件包。");
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
        catch
        {
        }
    }
}
