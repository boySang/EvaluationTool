using System;
using System.Threading.Tasks;
using AssessmentTool.Windows.Components;

namespace AssessmentTool.App.Services;

public interface IComponentStatusService
{
    Task<ComponentStatus> GetPlinkStatusAsync();

    Task<ComponentInstallPreview> PreparePlinkInstallAsync(string sourcePath);

    Task<ComponentStatus> InstallPreparedPlinkAsync(ComponentInstallPreview preview);
}

public sealed class ComponentInstallPreview
{
    internal ComponentInstallPreview(
        string sourcePath,
        string fileName,
        long sizeBytes,
        string sha256)
    {
        SourcePath = string.IsNullOrWhiteSpace(sourcePath)
            ? throw new ArgumentException("组件来源路径不能为空。", nameof(sourcePath))
            : sourcePath;
        FileName = string.IsNullOrWhiteSpace(fileName)
            ? throw new ArgumentException("组件文件名不能为空。", nameof(fileName))
            : fileName;
        if (sizeBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sizeBytes));
        }

        SizeBytes = sizeBytes;
        Sha256 = string.IsNullOrWhiteSpace(sha256)
            ? throw new ArgumentException("组件哈希不能为空。", nameof(sha256))
            : sha256;
    }

    internal string SourcePath { get; }
    public string FileName { get; }
    public long SizeBytes { get; }
    public string Sha256 { get; }
}
