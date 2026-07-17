using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Windows.Storage;
using Microsoft.Win32;

namespace AssessmentTool.App.Services;

public interface ICommandDraftService
{
    Task<IReadOnlyList<CommandDraftArchiveRecord>> LoadAsync(
        CancellationToken cancellationToken = default);
    Task<CommandDraftArchiveRecord> ImportAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}

public interface ICommandDraftFilePicker
{
    string? SelectJsonFile();
}

public sealed class JsonCommandDraftFilePicker : ICommandDraftFilePicker
{
    public string? SelectJsonFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择命令草稿 JSON",
            Filter = "JSON 文件 (*.json)|*.json",
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}

public sealed class CommandDraftService : ICommandDraftService
{
    private readonly ICommandDraftRepository repository;
    private readonly CommandDraftImporter importer;

    public CommandDraftService(ICommandDraftRepository repository)
        : this(repository, new CommandDraftImporter())
    {
    }

    internal CommandDraftService(
        ICommandDraftRepository repository,
        CommandDraftImporter importer)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.importer = importer ?? throw new ArgumentNullException(nameof(importer));
    }

    public Task<IReadOnlyList<CommandDraftArchiveRecord>> LoadAsync(
        CancellationToken cancellationToken = default)
    {
        return repository.GetCommandDraftsAsync(cancellationToken);
    }

    public async Task<CommandDraftArchiveRecord> ImportAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("请选择要导入的 JSON 文件。", nameof(filePath));
        }

        byte[] bytes;
        try
        {
            using (var stream = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                81920,
                useAsync: true))
            {
                if (stream.Length > CommandDraftImporter.MaximumImportBytes)
                {
                    throw new CommandDraftImportException("导入文件超过 1 MB 限制。请拆分后重新导入。");
                }

                bytes = new byte[checked((int)stream.Length)];
                var offset = 0;
                while (offset < bytes.Length)
                {
                    var read = await stream.ReadAsync(
                        bytes,
                        offset,
                        bytes.Length - offset,
                        cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new EndOfStreamException("导入文件读取不完整。");
                    }

                    offset += read;
                }
            }
        }
        catch (CommandDraftImportException)
        {
            throw;
        }
        catch (Exception exception) when (!(exception is OperationCanceledException))
        {
            throw new CommandDraftImportException("无法读取命令草稿文件。请检查文件权限后重试。", exception);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var draft = importer.Import(bytes, Path.GetFileName(filePath), DateTimeOffset.UtcNow);
        var id = await repository.SaveCommandDraftAsync(draft, cancellationToken).ConfigureAwait(false);
        return new CommandDraftArchiveRecord(
            id,
            draft.SourceFileName,
            draft.RawSha256,
            draft.RawJson,
            draft.ImportedAt,
            draft.Commands,
            draft.Findings);
    }
}
