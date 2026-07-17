using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public interface IProjectEvidenceFolderLauncher
{
    Task OpenAsync(ProjectId projectId, CancellationToken cancellationToken = default);
}

public sealed class ProjectEvidenceFolderLauncher : IProjectEvidenceFolderLauncher
{
    private readonly IProjectRepository repository;

    public ProjectEvidenceFolderLauncher(IProjectRepository repository)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    public async Task OpenAsync(ProjectId projectId, CancellationToken cancellationToken = default)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("请先选择有效项目。", nameof(projectId));
        }

        var projects = await repository.GetProjectsAsync(cancellationToken).ConfigureAwait(false);
        var project = projects.SingleOrDefault(candidate => candidate.Id.Equals(projectId));
        if (project == null)
        {
            throw new InvalidOperationException("当前项目不存在，已阻止打开证据目录。");
        }

        var directory = WindowsEvidenceRootPolicy.Normalize(project.EvidenceRoot, nameof(project.EvidenceRoot));
        WindowsEvidenceRootPolicy.EnsureNoExistingReparsePoints(directory);
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("项目证据目录尚未生成，请先完成一次只读采集。");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var explorerPath = Path.Combine(windowsDirectory, "explorer.exe");
        if (string.IsNullOrWhiteSpace(windowsDirectory) || !File.Exists(explorerPath))
        {
            throw new FileNotFoundException("无法找到 Windows 资源管理器。");
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = explorerPath,
            Arguments = SerializeArgument(directory),
            UseShellExecute = false,
            CreateNoWindow = true
        });
    }

    internal static string SerializeArgument(string value)
    {
        if (value.IndexOf('\0') >= 0 || value.IndexOf('\r') >= 0 || value.IndexOf('\n') >= 0)
        {
            throw new ArgumentException("目录路径包含无效控制字符。", nameof(value));
        }

        var result = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                result.Append('\\', (backslashes * 2) + 1);
                result.Append('"');
                backslashes = 0;
                continue;
            }

            result.Append('\\', backslashes);
            result.Append(character);
            backslashes = 0;
        }

        result.Append('\\', backslashes * 2);
        result.Append('"');
        return result.ToString();
    }
}

internal sealed class UnavailableProjectEvidenceFolderLauncher : IProjectEvidenceFolderLauncher
{
    public Task OpenAsync(ProjectId projectId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException("证据目录服务尚未初始化。");
    }
}
