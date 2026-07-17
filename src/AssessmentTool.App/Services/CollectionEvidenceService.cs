using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Evidence;
using AssessmentTool.Windows.Evidence;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public sealed class CollectionEvidenceService : ICollectionEvidenceService
{
    private const string RawOutputFileName = "原始输出.txt";
    private const string ManifestFileName = "执行记录.json";
    private const string IndexFailureMarkerFileName = "待入库.txt";
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

    private readonly IProjectRepository repository;
    private readonly WpfEvidenceRenderer renderer;

    public CollectionEvidenceService(IProjectRepository repository)
        : this(repository, new WpfEvidenceRenderer(1400, 900))
    {
    }

    public CollectionEvidenceService(IProjectRepository repository, WpfEvidenceRenderer renderer)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.renderer = renderer ?? throw new ArgumentNullException(nameof(renderer));
    }

    public async Task<SavedCollectionEvidence> SaveAsync(
        ProjectRecord project,
        DeviceRecord device,
        string commandPackVersion,
        CommandDefinition command,
        CommandOutput output,
        CancellationToken cancellationToken = default)
    {
        ValidateInput(project, device, commandPackVersion, command, output);
        cancellationToken.ThrowIfCancellationRequested();

        var rawOutput = CombineOutput(output);
        var pathBuilder = new EvidencePathBuilder(project.EvidenceRoot);
        var batchDirectory = pathBuilder.CreateBatchDirectory(
            project.ProjectName,
            device.DisplayName,
            command.CheckItem,
            output.StartedAt);
        var relativeBatchDirectory = MakeRelativePath(project.EvidenceRoot, batchDirectory);

        IReadOnlyList<RenderedEvidencePage> renderedPages = Array.Empty<RenderedEvidencePage>();
        Exception? renderingFailure = null;
        if (!string.IsNullOrWhiteSpace(rawOutput))
        {
            try
            {
                renderedPages = await RenderOnStaAsync(
                    rawOutput,
                    new EvidenceHeader(
                        project.ProjectName,
                        device.DisplayName,
                        command.CheckItem,
                        command.CommandText,
                        output.CompletedAt),
                    batchDirectory).ConfigureAwait(false);
            }
            catch (Exception error)
            {
                renderingFailure = error;
                DeleteIncompletePages(batchDirectory);
            }
        }
        else
        {
            renderingFailure = new InvalidDataException("命令没有返回可生成截图的输出。");
        }

        var executionStatus = renderingFailure != null && output.Outcome == RemoteExecutionOutcome.Succeeded
            ? ExecutionStatus.Failed
            : MapStatus(output.Outcome);
        var errorText = BuildErrorText(output, renderingFailure);
        var localRecord = CreateRecord(
            project,
            device,
            commandPackVersion,
            command,
            output,
            executionStatus,
            RawOutputFileName,
            renderedPages.Select(page => Path.GetFileName(page.Path)),
            renderedPages.ToDictionary(
                page => Path.GetFileName(page.Path),
                page => page.Sha256,
                StringComparer.OrdinalIgnoreCase),
            rawOutput,
            errorText);

        EvidenceManifest.FromExecutionRecord(
                localRecord,
                output.FailureCategory?.ToString()
                    ?? (renderingFailure == null ? null : "EvidenceRenderingFailed"))
            .WriteToDirectory(batchDirectory, rawOutput);

        var persistedRecord = CreateRecord(
            project,
            device,
            commandPackVersion,
            command,
            output,
            executionStatus,
            CombineRelativePath(relativeBatchDirectory, RawOutputFileName),
            renderedPages.Select(page => CombineRelativePath(relativeBatchDirectory, Path.GetFileName(page.Path))),
            renderedPages.ToDictionary(
                page => CombineRelativePath(relativeBatchDirectory, Path.GetFileName(page.Path)),
                page => page.Sha256,
                StringComparer.OrdinalIgnoreCase),
            rawOutput,
            errorText);
        var imagePaths = new ReadOnlyCollection<string>(renderedPages.Select(page => page.Path).ToArray());
        var manifestPath = Path.Combine(batchDirectory, ManifestFileName);

        try
        {
            await repository.SaveExecutionAsync(persistedRecord, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception repositoryError)
        {
            WriteIndexFailureMarker(batchDirectory);
            var unindexed = new SavedCollectionEvidence(
                batchDirectory,
                manifestPath,
                persistedRecord,
                imagePaths,
                isIndexed: false);
            throw new CollectionEvidenceException(
                "证据文件已安全保存，但执行记录未能写入项目索引；软件已留下待恢复标记。",
                unindexed,
                repositoryError);
        }

        var saved = new SavedCollectionEvidence(
            batchDirectory,
            manifestPath,
            persistedRecord,
            imagePaths,
            isIndexed: true);
        if (renderingFailure != null)
        {
            throw new CollectionEvidenceException(
                "原始输出和失败记录已保存，但证据截图生成失败。",
                saved,
                renderingFailure);
        }

        return saved;
    }

    private static void ValidateInput(
        ProjectRecord project,
        DeviceRecord device,
        string commandPackVersion,
        CommandDefinition command,
        CommandOutput output)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        if (device == null)
        {
            throw new ArgumentNullException(nameof(device));
        }

        if (!device.ProjectId.Equals(project.Id))
        {
            throw new ArgumentException("设备不属于指定项目。", nameof(device));
        }

        if (string.IsNullOrWhiteSpace(commandPackVersion) || commandPackVersion.Any(char.IsControl))
        {
            throw new ArgumentException("命令包版本不能为空或包含控制字符。", nameof(commandPackVersion));
        }

        if (command == null)
        {
            throw new ArgumentNullException(nameof(command));
        }

        if (output == null)
        {
            throw new ArgumentNullException(nameof(output));
        }

        if (!string.Equals(command.Id, output.CommandId, StringComparison.Ordinal))
        {
            throw new ArgumentException("命令输出与命令定义不匹配。", nameof(output));
        }
    }

    private static ExecutionRecord CreateRecord(
        ProjectRecord project,
        DeviceRecord device,
        string commandPackVersion,
        CommandDefinition command,
        CommandOutput output,
        ExecutionStatus status,
        string rawOutputPath,
        IEnumerable<string> imagePaths,
        IDictionary<string, string> imageHashes,
        string rawOutput,
        string? errorText)
    {
        return new ExecutionRecord(
            project.Id.ToString(),
            device.Id.ToString(),
            device.Protocol,
            commandPackVersion.Trim(),
            command.Id,
            command.CommandText,
            output.StartedAt,
            output.CompletedAt,
            status,
            output.ExitCode,
            rawOutputPath,
            ComputeSha256(rawOutput),
            imagePaths,
            imageHashes,
            errorText);
    }

    private static string CombineOutput(CommandOutput output)
    {
        if (output.StandardOutput.Length == 0)
        {
            return output.StandardError;
        }

        if (output.StandardError.Length == 0)
        {
            return output.StandardOutput;
        }

        var separator = output.StandardOutput.EndsWith("\n", StringComparison.Ordinal)
            ? string.Empty
            : Environment.NewLine;
        return output.StandardOutput + separator + output.StandardError;
    }

    private static string? BuildErrorText(CommandOutput output, Exception? renderingFailure)
    {
        if (renderingFailure != null)
        {
            var renderingMessage =
                "证据截图生成失败；原始输出已保存，技术类型：" + renderingFailure.GetType().Name;
            return output.Outcome == RemoteExecutionOutcome.Succeeded
                ? renderingMessage
                : output.UserErrorMessage + " " + renderingMessage;
        }

        return output.Outcome == RemoteExecutionOutcome.Succeeded
            ? null
            : output.UserErrorMessage;
    }

    private static ExecutionStatus MapStatus(RemoteExecutionOutcome outcome)
    {
        switch (outcome)
        {
            case RemoteExecutionOutcome.Succeeded:
                return ExecutionStatus.Succeeded;
            case RemoteExecutionOutcome.Failed:
                return ExecutionStatus.Failed;
            case RemoteExecutionOutcome.Stopped:
                return ExecutionStatus.Stopped;
            default:
                throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "远程执行结果无效。");
        }
    }

    private Task<IReadOnlyList<RenderedEvidencePage>> RenderOnStaAsync(
        string rawOutput,
        EvidenceHeader header,
        string batchDirectory)
    {
        var completion = new TaskCompletionSource<IReadOnlyList<RenderedEvidencePage>>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                completion.SetResult(renderer.Render(rawOutput, header, batchDirectory));
            }
            catch (Exception error)
            {
                completion.SetException(error);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Name = "AssessmentTool Evidence Renderer";
        thread.Start();
        return completion.Task;
    }

    private static void DeleteIncompletePages(string batchDirectory)
    {
        foreach (var path in Directory.EnumerateFiles(batchDirectory, "证据_*.png", SearchOption.TopDirectoryOnly))
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static string MakeRelativePath(string root, string path)
    {
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var normalizedPath = Path.GetFullPath(path);
        if (!normalizedPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("证据批次目录超出项目证据根目录。");
        }

        return normalizedPath.Substring(normalizedRoot.Length);
    }

    private static string CombineRelativePath(string directory, string fileName)
    {
        return string.IsNullOrEmpty(directory) ? fileName : Path.Combine(directory, fileName);
    }

    private static string ComputeSha256(string value)
    {
        using (var sha256 = SHA256.Create())
        {
            return ToHex(sha256.ComputeHash(StrictUtf8.GetBytes(value)));
        }
    }

    private static string ToHex(IEnumerable<byte> bytes)
    {
        return string.Concat(bytes.Select(value => value.ToString("x2", CultureInfo.InvariantCulture)));
    }

    private static void WriteIndexFailureMarker(string batchDirectory)
    {
        File.WriteAllText(
            Path.Combine(batchDirectory, IndexFailureMarkerFileName),
            "证据文件已完成，但项目数据库索引写入失败。请勿删除本目录，后续可从执行记录.json恢复。\r\n",
            StrictUtf8);
    }
}
