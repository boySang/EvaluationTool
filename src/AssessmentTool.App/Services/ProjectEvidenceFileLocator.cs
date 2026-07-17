using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public interface IProjectEvidenceFileLocator
{
    Task ShowInFolderAsync(
        ProjectId projectId,
        string relativePath,
        CancellationToken cancellationToken = default);
}

public sealed class ProjectEvidenceFileLocator : IProjectEvidenceFileLocator
{
    private readonly IProjectRepository repository;
    private readonly Action<ProcessStartInfo> startProcess;

    public ProjectEvidenceFileLocator(IProjectRepository repository)
        : this(repository, processStartInfo => Process.Start(processStartInfo))
    {
    }

    internal ProjectEvidenceFileLocator(
        IProjectRepository repository,
        Action<ProcessStartInfo> startProcess)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.startProcess = startProcess ?? throw new ArgumentNullException(nameof(startProcess));
    }

    public async Task ShowInFolderAsync(
        ProjectId projectId,
        string relativePath,
        CancellationToken cancellationToken = default)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("请先选择有效项目。", nameof(projectId));
        }

        var projects = await repository.GetProjectsAsync(cancellationToken).ConfigureAwait(false);
        var project = projects.SingleOrDefault(candidate => candidate.Id.Equals(projectId));
        if (project == null)
        {
            throw new InvalidOperationException("当前项目不存在，已阻止定位证据文件。");
        }

        var indexedFiles = await repository.GetEvidenceFilesAsync(projectId, cancellationToken)
            .ConfigureAwait(false);
        var normalizedRelativePath = RequireUniqueIndexedPath(projectId, indexedFiles, relativePath);

        var root = WindowsEvidenceRootPolicy.Normalize(project.EvidenceRoot, nameof(project.EvidenceRoot));
        WindowsEvidenceRootPolicy.EnsureNoExistingReparsePoints(root);
        var path = WindowsEvidenceRootPolicy.ResolveContainedPath(
            root,
            normalizedRelativePath,
            nameof(relativePath));
        EnsureNoReparsePoints(root, path);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("证据文件不存在，请先执行文件 SHA-256 复核。", path);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var explorerPath = Path.Combine(windowsDirectory, "explorer.exe");
        if (string.IsNullOrWhiteSpace(windowsDirectory) || !File.Exists(explorerPath))
        {
            throw new FileNotFoundException("无法找到 Windows 资源管理器。");
        }

        startProcess(new ProcessStartInfo
        {
            FileName = explorerPath,
            Arguments = SerializeSelectArgument(path),
            UseShellExecute = false,
            CreateNoWindow = true
        });
    }

    internal static string SerializeSelectArgument(string path)
    {
        return "/select," + ProjectEvidenceFolderLauncher.SerializeArgument(path);
    }

    internal static string RequireUniqueIndexedPath(
        ProjectId projectId,
        System.Collections.Generic.IEnumerable<EvidenceFileRecord> indexedFiles,
        string relativePath)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("请先选择有效项目。", nameof(projectId));
        }

        if (indexedFiles == null)
        {
            throw new ArgumentNullException(nameof(indexedFiles));
        }

        var normalizedRelativePath = WindowsEvidenceRelativePathPolicy.Normalize(
            relativePath,
            nameof(relativePath));
        var records = indexedFiles.ToArray();
        if (records.Any(file => file == null || !file.ProjectId.Equals(projectId))
            || records.Count(file => string.Equals(
                file.RelativePath,
                normalizedRelativePath,
                StringComparison.OrdinalIgnoreCase)) != 1)
        {
            throw new InvalidDataException("该路径不是当前项目中唯一有效的证据索引记录。");
        }

        return normalizedRelativePath;
    }

    private static void EnsureNoReparsePoints(string root, string filePath)
    {
        var relativePath = filePath.Substring(root.Length)
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = root;
        foreach (var segment in relativePath.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((Directory.Exists(current) || File.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("证据路径包含 Windows 重解析点，已阻止打开。");
            }
        }
    }
}

internal sealed class UnavailableProjectEvidenceFileLocator : IProjectEvidenceFileLocator
{
    public Task ShowInFolderAsync(
        ProjectId projectId,
        string relativePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException("证据文件定位服务尚未初始化。");
    }
}
