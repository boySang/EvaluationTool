using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.ViewModels;

public enum EvidenceCenterViewModelState
{
    NoProject,
    Loading,
    Ready,
    Empty,
    Failed
}

public sealed class EvidenceCenterViewModel : INotifyPropertyChanged
{
    private readonly object loadSync = new object();
    private readonly IEvidenceCenterService service;
    private readonly IProjectEvidenceFolderLauncher folderLauncher;
    private readonly IProjectEvidenceFileLocator fileLocator;
    private readonly IProjectEvidenceManifestExporter manifestExporter;
    private readonly IEvidenceManifestExportFilePicker exportFilePicker;
    private readonly bool exportAvailable;
    private readonly IEvidenceRecoveryService? recoveryService;
    private readonly DelegateCommand refreshCommand;
    private readonly DelegateCommand verifyCommand;
    private readonly DelegateCommand openFolderCommand;
    private readonly DelegateCommand recoverCommand;
    private readonly ParameterizedDelegateCommand<EvidenceCenterItem> openRawOutputCommand;
    private readonly ParameterizedDelegateCommand<EvidenceCenterItem> openFirstScreenshotCommand;
    private readonly DelegateCommand exportManifestCommand;
    private IReadOnlyList<EvidenceCenterItem> items = Array.Empty<EvidenceCenterItem>();
    private IReadOnlyList<DatabaseConfirmationAuditItem> databaseConfirmations =
        Array.Empty<DatabaseConfirmationAuditItem>();
    private IReadOnlyList<HostSoftwareDiscoveryAuditItem> hostSoftwareDiscoveries =
        Array.Empty<HostSoftwareDiscoveryAuditItem>();
    private ProjectRecord? selectedProject;
    private EvidenceCenterViewModelState state = EvidenceCenterViewModelState.NoProject;
    private Task? activeLoad;
    private int activeLoadGeneration;
    private bool activeLoadVerifiesFiles;
    private int selectionGeneration;
    private string whatHappened = string.Empty;
    private string possibleCause = string.Empty;
    private string howToFix = string.Empty;
    private string technicalDetails = string.Empty;
    private string verificationSummary = "尚未读取证据文件进行 SHA-256 复核。";
    private string recoverySummary = "仅在证据文件已保存但本地索引写入失败时需要恢复。";
    private string exportSummary = "导出会先只读复核证据文件，再生成不含凭据和原始输出正文的 JSON 清单。";

    public EvidenceCenterViewModel(
        IEvidenceCenterService service,
        IProjectEvidenceFolderLauncher? folderLauncher = null,
        IEvidenceRecoveryService? recoveryService = null,
        IProjectEvidenceFileLocator? fileLocator = null,
        IProjectEvidenceManifestExporter? manifestExporter = null,
        IEvidenceManifestExportFilePicker? exportFilePicker = null)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
        this.folderLauncher = folderLauncher ?? new UnavailableProjectEvidenceFolderLauncher();
        this.recoveryService = recoveryService;
        this.fileLocator = fileLocator ?? new UnavailableProjectEvidenceFileLocator();
        this.manifestExporter = manifestExporter ?? new UnavailableEvidenceManifestExporter();
        this.exportFilePicker = exportFilePicker ?? new UnavailableEvidenceManifestExportFilePicker();
        exportAvailable = manifestExporter != null && exportFilePicker != null;
        refreshCommand = new DelegateCommand(() => _ = RefreshAsync(), () => CanRefresh);
        verifyCommand = new DelegateCommand(() => _ = VerifyAsync(), () => CanVerify);
        openFolderCommand = new DelegateCommand(() => _ = OpenEvidenceFolderAsync(), () => CanOpenFolder);
        recoverCommand = new DelegateCommand(() => _ = RecoverPendingEvidenceAsync(), () => CanRecover);
        openRawOutputCommand = new ParameterizedDelegateCommand<EvidenceCenterItem>(
            item => _ = ShowEvidenceFileAsync(item.RawOutputPath),
            item => CanLocateFiles && item.HasRawOutput);
        openFirstScreenshotCommand = new ParameterizedDelegateCommand<EvidenceCenterItem>(
            item => _ = ShowEvidenceFileAsync(item.FirstScreenshotPath),
            item => CanLocateFiles && item.HasScreenshots);
        exportManifestCommand = new DelegateCommand(
            () => _ = ExportManifestAsync(),
            () => CanExportManifest);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ProjectRecord? SelectedProject => selectedProject;
    public IReadOnlyList<EvidenceCenterItem> Items => items;
    public IReadOnlyList<DatabaseConfirmationAuditItem> DatabaseConfirmations => databaseConfirmations;
    public IReadOnlyList<HostSoftwareDiscoveryAuditItem> HostSoftwareDiscoveries => hostSoftwareDiscoveries;
    public EvidenceCenterViewModelState State => state;
    public ICommand RefreshCommand => refreshCommand;
    public ICommand VerifyCommand => verifyCommand;
    public ICommand OpenFolderCommand => openFolderCommand;
    public ICommand RecoverCommand => recoverCommand;
    public ICommand OpenRawOutputCommand => openRawOutputCommand;
    public ICommand OpenFirstScreenshotCommand => openFirstScreenshotCommand;
    public ICommand ExportManifestCommand => exportManifestCommand;
    public bool CanRefresh => selectedProject != null && State != EvidenceCenterViewModelState.Loading;
    public bool CanVerify => selectedProject != null && HasItems && State != EvidenceCenterViewModelState.Loading;
    public bool CanOpenFolder => selectedProject != null && State != EvidenceCenterViewModelState.Loading;
    public bool CanRecover => recoveryService != null
        && selectedProject != null
        && State != EvidenceCenterViewModelState.Loading;
    public bool CanLocateFiles => selectedProject != null
        && State != EvidenceCenterViewModelState.Loading;
    public bool CanExportManifest => exportAvailable
        && selectedProject != null
        && State != EvidenceCenterViewModelState.Loading;
    public bool HasItems => Items.Count != 0;
    public bool HasDatabaseConfirmations => DatabaseConfirmations.Count != 0;
    public bool HasHostSoftwareDiscoveries => HostSoftwareDiscoveries.Count != 0;
    public string WhatHappened => whatHappened;
    public string PossibleCause => possibleCause;
    public string HowToFix => howToFix;
    public string TechnicalDetails => technicalDetails;
    public string VerificationSummary => verificationSummary;
    public string RecoverySummary => recoverySummary;
    public string ExportSummary => exportSummary;

    public Task SelectProjectAsync(ProjectRecord? project)
    {
        var generation = unchecked(++selectionGeneration);
        selectedProject = project;
        OnPropertyChanged(nameof(SelectedProject));
        ClearError();
        SetVerificationSummary("尚未读取证据文件进行 SHA-256 复核。");
        SetRecoverySummary("仅在证据文件已保存但本地索引写入失败时需要恢复。");
        SetExportSummary("导出会先只读复核证据文件，再生成不含凭据和原始输出正文的 JSON 清单。");
        SetItems(Array.Empty<EvidenceCenterItem>());
        SetDatabaseConfirmations(Array.Empty<DatabaseConfirmationAuditItem>());
        SetHostSoftwareDiscoveries(Array.Empty<HostSoftwareDiscoveryAuditItem>());

        if (project == null)
        {
            SetState(EvidenceCenterViewModelState.NoProject);
            return Task.CompletedTask;
        }

        return BeginLoad(project, generation, verifyFiles: false);
    }

    public Task RefreshAsync()
    {
        var project = selectedProject;
        if (project == null)
        {
            return Task.CompletedTask;
        }

        return BeginLoad(project, selectionGeneration, verifyFiles: false);
    }

    public Task VerifyAsync()
    {
        var project = selectedProject;
        if (project == null || !HasItems)
        {
            return Task.CompletedTask;
        }

        return BeginLoad(project, selectionGeneration, verifyFiles: true);
    }

    public async Task OpenEvidenceFolderAsync()
    {
        var project = selectedProject;
        if (project == null)
        {
            return;
        }

        try
        {
            ClearError();
            await folderLauncher.OpenAsync(project.Id);
        }
        catch (Exception exception)
        {
            whatHappened = "证据目录打开失败";
            possibleCause = exception is System.IO.DirectoryNotFoundException
                ? "当前项目还没有生成证据目录"
                : "目录不存在、不可访问，或路径安全检查未通过";
            howToFix = "请先完成一次只读采集；如目录已经存在，请检查目录权限后重试。";
            technicalDetails = exception.GetType().Name;
            OnPropertyChanged(nameof(WhatHappened));
            OnPropertyChanged(nameof(PossibleCause));
            OnPropertyChanged(nameof(HowToFix));
            OnPropertyChanged(nameof(TechnicalDetails));
            SetState(EvidenceCenterViewModelState.Failed);
        }
    }

    public async Task ShowEvidenceFileAsync(string? relativePath)
    {
        var project = selectedProject;
        if (project == null || string.IsNullOrWhiteSpace(relativePath))
        {
            return;
        }

        try
        {
            ClearError();
            await fileLocator.ShowInFolderAsync(project.Id, relativePath!);
        }
        catch (Exception exception)
        {
            whatHappened = "证据文件定位失败";
            possibleCause = exception is System.IO.FileNotFoundException
                ? "证据文件已被移动、删除，或项目目录不可访问"
                : "该文件不在当前项目证据索引中，或路径安全检查未通过";
            howToFix = "请先单击“复核文件 SHA-256”；如文件缺失，请保留当前记录并重新采集对应测评项。";
            technicalDetails = exception.GetType().Name;
            OnPropertyChanged(nameof(WhatHappened));
            OnPropertyChanged(nameof(PossibleCause));
            OnPropertyChanged(nameof(HowToFix));
            OnPropertyChanged(nameof(TechnicalDetails));
            SetState(EvidenceCenterViewModelState.Failed);
        }
    }

    public async Task ExportManifestAsync()
    {
        var project = selectedProject;
        if (project == null || !exportAvailable)
        {
            return;
        }

        try
        {
            ClearError();
            var destinationPath = exportFilePicker.SelectDestination(project);
            if (string.IsNullOrWhiteSpace(destinationPath))
            {
                return;
            }

            SetState(EvidenceCenterViewModelState.Loading);
            var result = await manifestExporter.ExportAsync(
                project,
                destinationPath!,
                CancellationToken.None);
            SetExportSummary(result.Summary + " 保存位置：" + result.Path);
            SetState(EvidenceCenterViewModelState.Ready);
        }
        catch (Exception exception)
        {
            whatHappened = "项目证据清单导出失败";
            possibleCause = exception is System.IO.IOException
                ? "目标文件已存在、磁盘空间不足，或导出目录不可写"
                : "项目索引、证据文件或审计历史未能通过完整性检查";
            howToFix = "请选择新的 JSON 文件名并重试；如仍失败，请先执行“复核文件 SHA-256”并处理异常证据。";
            technicalDetails = exception.GetType().Name;
            OnPropertyChanged(nameof(WhatHappened));
            OnPropertyChanged(nameof(PossibleCause));
            OnPropertyChanged(nameof(HowToFix));
            OnPropertyChanged(nameof(TechnicalDetails));
            SetState(EvidenceCenterViewModelState.Failed);
        }
    }

    public async Task RecoverPendingEvidenceAsync()
    {
        var project = selectedProject;
        if (project == null || recoveryService == null)
        {
            return;
        }

        var generation = selectionGeneration;
        ClearError();
        SetState(EvidenceCenterViewModelState.Loading);
        try
        {
            var result = await recoveryService.RecoverAsync(project, CancellationToken.None);
            if (!IsCurrent(project, generation))
            {
                return;
            }

            SetRecoverySummary(result.Summary);
            await LoadCoreAsync(project, generation, verifyFiles: false);
        }
        catch (Exception exception)
        {
            if (!IsCurrent(project, generation))
            {
                return;
            }

            whatHappened = "待入库证据恢复失败";
            possibleCause = "证据目录不可访问、执行清单损坏，或文件与 SHA-256 不一致";
            howToFix = "请保留带“待入库.txt”的批次目录，检查磁盘和目录权限后重试；不要手工修改执行记录。";
            technicalDetails = exception.GetType().Name;
            OnPropertyChanged(nameof(WhatHappened));
            OnPropertyChanged(nameof(PossibleCause));
            OnPropertyChanged(nameof(HowToFix));
            OnPropertyChanged(nameof(TechnicalDetails));
            SetState(EvidenceCenterViewModelState.Failed);
        }
    }

    private Task BeginLoad(ProjectRecord project, int generation, bool verifyFiles)
    {
        lock (loadSync)
        {
            if (activeLoad != null && !activeLoad.IsCompleted && activeLoadGeneration == generation)
            {
                if (activeLoadVerifiesFiles == verifyFiles)
                {
                    return activeLoad;
                }

                var previousLoad = activeLoad;
                activeLoadVerifiesFiles = verifyFiles;
                activeLoad = ContinueAfterAsync(previousLoad, project, generation, verifyFiles);
                return activeLoad;
            }

            activeLoadGeneration = generation;
            activeLoadVerifiesFiles = verifyFiles;
            activeLoad = LoadCoreAsync(project, generation, verifyFiles);
            return activeLoad;
        }
    }

    private async Task ContinueAfterAsync(
        Task previousLoad,
        ProjectRecord project,
        int generation,
        bool verifyFiles)
    {
        await previousLoad;
        if (IsCurrent(project, generation))
        {
            await LoadCoreAsync(project, generation, verifyFiles);
        }
    }

    private async Task LoadCoreAsync(ProjectRecord project, int generation, bool verifyFiles)
    {
        ClearError();
        SetState(EvidenceCenterViewModelState.Loading);
        try
        {
            var snapshot = verifyFiles
                ? await service.VerifyAsync(project.Id)
                : await service.LoadAsync(project.Id);
            if (!IsCurrent(project, generation))
            {
                return;
            }

            SetItems(snapshot.Items);
            SetDatabaseConfirmations(snapshot.DatabaseConfirmations);
            SetHostSoftwareDiscoveries(snapshot.HostSoftwareDiscoveries);
            if (verifyFiles)
            {
                var verified = Items.Count(item => item.ShaStatus == EvidenceShaStatus.Verified);
                var problems = Items.Count(item => item.ShaStatus != EvidenceShaStatus.Verified
                    && item.ShaStatus != EvidenceShaStatus.NotAvailable);
                SetVerificationSummary(
                    "本次已读取证据文件：" + verified + " 条与索引 SHA-256 一致，" + problems + " 条需要处理。复核时间："
                    + DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            SetState(Items.Count == 0
                && DatabaseConfirmations.Count == 0
                && HostSoftwareDiscoveries.Count == 0
                ? EvidenceCenterViewModelState.Empty
                : EvidenceCenterViewModelState.Ready);
        }
        catch (Exception exception)
        {
            if (IsCurrent(project, generation))
            {
                SetFailure(exception);
            }
        }
    }

    private bool IsCurrent(ProjectRecord project, int generation)
    {
        return generation == selectionGeneration
            && selectedProject != null
            && selectedProject.Id.Equals(project.Id);
    }

    private void SetFailure(Exception exception)
    {
        whatHappened = "证据记录加载失败";
        possibleCause = exception is EvidenceCenterException evidenceError
            && evidenceError.Failure == EvidenceCenterFailure.InvalidProject
                ? "当前项目无效"
                : "本地项目数据库或证据索引暂时不可用";
        howToFix = "重新选择项目或单击“刷新”；如仍失败，请检查本机数据目录权限。";
        technicalDetails = exception.GetType().Name;
        OnPropertyChanged(nameof(WhatHappened));
        OnPropertyChanged(nameof(PossibleCause));
        OnPropertyChanged(nameof(HowToFix));
        OnPropertyChanged(nameof(TechnicalDetails));
        SetState(EvidenceCenterViewModelState.Failed);
    }

    private void ClearError()
    {
        whatHappened = string.Empty;
        possibleCause = string.Empty;
        howToFix = string.Empty;
        technicalDetails = string.Empty;
        OnPropertyChanged(nameof(WhatHappened));
        OnPropertyChanged(nameof(PossibleCause));
        OnPropertyChanged(nameof(HowToFix));
        OnPropertyChanged(nameof(TechnicalDetails));
    }

    private void SetItems(IEnumerable<EvidenceCenterItem> value)
    {
        items = new ReadOnlyCollection<EvidenceCenterItem>(value.ToArray());
        OnPropertyChanged(nameof(Items));
        OnPropertyChanged(nameof(HasItems));
        OnPropertyChanged(nameof(CanVerify));
        verifyCommand.RaiseCanExecuteChanged();
    }

    private void SetDatabaseConfirmations(IEnumerable<DatabaseConfirmationAuditItem> value)
    {
        databaseConfirmations = new ReadOnlyCollection<DatabaseConfirmationAuditItem>(value.ToArray());
        OnPropertyChanged(nameof(DatabaseConfirmations));
        OnPropertyChanged(nameof(HasDatabaseConfirmations));
    }

    private void SetHostSoftwareDiscoveries(IEnumerable<HostSoftwareDiscoveryAuditItem> value)
    {
        hostSoftwareDiscoveries = new ReadOnlyCollection<HostSoftwareDiscoveryAuditItem>(value.ToArray());
        OnPropertyChanged(nameof(HostSoftwareDiscoveries));
        OnPropertyChanged(nameof(HasHostSoftwareDiscoveries));
    }

    private void SetState(EvidenceCenterViewModelState value)
    {
        if (state == value)
        {
            return;
        }

        state = value;
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(CanRefresh));
        OnPropertyChanged(nameof(CanVerify));
        OnPropertyChanged(nameof(CanOpenFolder));
        OnPropertyChanged(nameof(CanRecover));
        OnPropertyChanged(nameof(CanLocateFiles));
        OnPropertyChanged(nameof(CanExportManifest));
        refreshCommand.RaiseCanExecuteChanged();
        verifyCommand.RaiseCanExecuteChanged();
        openFolderCommand.RaiseCanExecuteChanged();
        recoverCommand.RaiseCanExecuteChanged();
        openRawOutputCommand.RaiseCanExecuteChanged();
        openFirstScreenshotCommand.RaiseCanExecuteChanged();
        exportManifestCommand.RaiseCanExecuteChanged();
    }

    private void SetVerificationSummary(string value)
    {
        verificationSummary = value;
        OnPropertyChanged(nameof(VerificationSummary));
    }

    private void SetRecoverySummary(string value)
    {
        recoverySummary = value;
        OnPropertyChanged(nameof(RecoverySummary));
    }

    private void SetExportSummary(string value)
    {
        exportSummary = value;
        OnPropertyChanged(nameof(ExportSummary));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
