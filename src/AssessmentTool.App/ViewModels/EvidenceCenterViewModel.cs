using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
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
    private readonly DelegateCommand refreshCommand;
    private readonly DelegateCommand verifyCommand;
    private readonly DelegateCommand openFolderCommand;
    private IReadOnlyList<EvidenceCenterItem> items = Array.Empty<EvidenceCenterItem>();
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

    public EvidenceCenterViewModel(
        IEvidenceCenterService service,
        IProjectEvidenceFolderLauncher? folderLauncher = null)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
        this.folderLauncher = folderLauncher ?? new UnavailableProjectEvidenceFolderLauncher();
        refreshCommand = new DelegateCommand(() => _ = RefreshAsync(), () => CanRefresh);
        verifyCommand = new DelegateCommand(() => _ = VerifyAsync(), () => CanVerify);
        openFolderCommand = new DelegateCommand(() => _ = OpenEvidenceFolderAsync(), () => CanOpenFolder);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ProjectRecord? SelectedProject => selectedProject;
    public IReadOnlyList<EvidenceCenterItem> Items => items;
    public EvidenceCenterViewModelState State => state;
    public ICommand RefreshCommand => refreshCommand;
    public ICommand VerifyCommand => verifyCommand;
    public ICommand OpenFolderCommand => openFolderCommand;
    public bool CanRefresh => selectedProject != null && State != EvidenceCenterViewModelState.Loading;
    public bool CanVerify => selectedProject != null && HasItems && State != EvidenceCenterViewModelState.Loading;
    public bool CanOpenFolder => selectedProject != null && State != EvidenceCenterViewModelState.Loading;
    public bool HasItems => Items.Count != 0;
    public string WhatHappened => whatHappened;
    public string PossibleCause => possibleCause;
    public string HowToFix => howToFix;
    public string TechnicalDetails => technicalDetails;
    public string VerificationSummary => verificationSummary;

    public Task SelectProjectAsync(ProjectRecord? project)
    {
        var generation = unchecked(++selectionGeneration);
        selectedProject = project;
        OnPropertyChanged(nameof(SelectedProject));
        ClearError();
        SetVerificationSummary("尚未读取证据文件进行 SHA-256 复核。");
        SetItems(Array.Empty<EvidenceCenterItem>());

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
        refreshCommand.RaiseCanExecuteChanged();
        verifyCommand.RaiseCanExecuteChanged();
        openFolderCommand.RaiseCanExecuteChanged();
    }

    private void SetVerificationSummary(string value)
    {
        verificationSummary = value;
        OnPropertyChanged(nameof(VerificationSummary));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
