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
    private readonly DelegateCommand refreshCommand;
    private IReadOnlyList<EvidenceCenterItem> items = Array.Empty<EvidenceCenterItem>();
    private ProjectRecord? selectedProject;
    private EvidenceCenterViewModelState state = EvidenceCenterViewModelState.NoProject;
    private Task? activeLoad;
    private int activeLoadGeneration;
    private int selectionGeneration;
    private string whatHappened = string.Empty;
    private string possibleCause = string.Empty;
    private string howToFix = string.Empty;
    private string technicalDetails = string.Empty;

    public EvidenceCenterViewModel(IEvidenceCenterService service)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
        refreshCommand = new DelegateCommand(() => _ = RefreshAsync(), () => CanRefresh);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ProjectRecord? SelectedProject => selectedProject;
    public IReadOnlyList<EvidenceCenterItem> Items => items;
    public EvidenceCenterViewModelState State => state;
    public ICommand RefreshCommand => refreshCommand;
    public bool CanRefresh => selectedProject != null && State != EvidenceCenterViewModelState.Loading;
    public bool HasItems => Items.Count != 0;
    public string WhatHappened => whatHappened;
    public string PossibleCause => possibleCause;
    public string HowToFix => howToFix;
    public string TechnicalDetails => technicalDetails;

    public Task SelectProjectAsync(ProjectRecord? project)
    {
        var generation = unchecked(++selectionGeneration);
        selectedProject = project;
        OnPropertyChanged(nameof(SelectedProject));
        ClearError();
        SetItems(Array.Empty<EvidenceCenterItem>());

        if (project == null)
        {
            SetState(EvidenceCenterViewModelState.NoProject);
            return Task.CompletedTask;
        }

        return BeginLoad(project, generation);
    }

    public Task RefreshAsync()
    {
        var project = selectedProject;
        if (project == null)
        {
            return Task.CompletedTask;
        }

        return BeginLoad(project, selectionGeneration);
    }

    private Task BeginLoad(ProjectRecord project, int generation)
    {
        lock (loadSync)
        {
            if (activeLoad != null
                && !activeLoad.IsCompleted
                && activeLoadGeneration == generation)
            {
                return activeLoad;
            }

            activeLoadGeneration = generation;
            activeLoad = LoadCoreAsync(project, generation);
            return activeLoad;
        }
    }

    private async Task LoadCoreAsync(ProjectRecord project, int generation)
    {
        ClearError();
        SetState(EvidenceCenterViewModelState.Loading);
        try
        {
            var snapshot = await service.LoadAsync(project.Id);
            if (!IsCurrent(project, generation))
            {
                return;
            }

            SetItems(snapshot.Items);
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
        refreshCommand.RaiseCanExecuteChanged();
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
