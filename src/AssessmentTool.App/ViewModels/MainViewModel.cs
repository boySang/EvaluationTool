using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly DelegateCommand toggleThemeCommand;

    public MainViewModel(
        CollectionViewModel collection,
        ComponentCenterViewModel componentCenter,
        Action toggleTheme)
        : this(null, collection, componentCenter, toggleTheme)
    {
    }

    public MainViewModel(
        ProjectWorkspaceViewModel? workspace,
        CollectionViewModel collection,
        ComponentCenterViewModel componentCenter,
        Action toggleTheme)
        : this(workspace, collection, componentCenter, new DeviceConnectionViewModel(null), toggleTheme)
    {
    }

    public MainViewModel(
        ProjectWorkspaceViewModel? workspace,
        CollectionViewModel collection,
        ComponentCenterViewModel componentCenter,
        DeviceConnectionViewModel deviceConnection,
        Action toggleTheme,
        EvidenceCenterViewModel? evidenceCenter = null,
        CommandLibraryViewModel? commandLibrary = null,
        CollectionTaskHistoryViewModel? taskHistory = null)
    {
        Workspace = workspace;
        Collection = collection ?? throw new ArgumentNullException(nameof(collection));
        ComponentCenter = componentCenter ?? throw new ArgumentNullException(nameof(componentCenter));
        DeviceConnection = deviceConnection ?? throw new ArgumentNullException(nameof(deviceConnection));
        EvidenceCenter = evidenceCenter
            ?? new EvidenceCenterViewModel(new EmptyEvidenceCenterService());
        CommandLibrary = commandLibrary ?? CommandLibraryViewModel.CreateEmpty();
        TaskHistory = taskHistory ?? new CollectionTaskHistoryViewModel(new EmptyCollectionTaskRepository());
        DeviceEditor = new DeviceEditorViewModel();
        toggleThemeCommand = new DelegateCommand(
            toggleTheme ?? throw new ArgumentNullException(nameof(toggleTheme)),
            () => true);
        NavigationItems = new ReadOnlyCollection<NavigationItemViewModel>(new[]
        {
            NavigationItemViewModel.Available("首页"),
            NavigationItemViewModel.Available("项目"),
            NavigationItemViewModel.Available("设备"),
            NavigationItemViewModel.Available("采集任务"),
            NavigationItemViewModel.Available("证据"),
            NavigationItemViewModel.Available("命令库"),
            NavigationItemViewModel.Available("组件中心"),
            NavigationItemViewModel.Deferred("设置")
        });
        Collection.SetRequiredComponentAvailability(ComponentCenter.IsSshAvailable);
        Collection.PropertyChanged += OnCollectionPropertyChanged;
        ComponentCenter.PropertyChanged += OnComponentCenterPropertyChanged;
        DeviceConnection.PropertyChanged += OnDeviceConnectionPropertyChanged;
        if (Workspace != null)
        {
            Workspace.PropertyChanged += OnWorkspacePropertyChanged;
            _ = TaskHistory.SelectProjectAsync(Workspace.SelectedProject);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ProjectWorkspaceViewModel? Workspace { get; }
    public CollectionViewModel Collection { get; }
    public ComponentCenterViewModel ComponentCenter { get; }
    public DeviceConnectionViewModel DeviceConnection { get; }
    public EvidenceCenterViewModel EvidenceCenter { get; }
    public CommandLibraryViewModel CommandLibrary { get; }
    public CollectionTaskHistoryViewModel TaskHistory { get; }
    public DeviceEditorViewModel DeviceEditor { get; }
    public IReadOnlyList<NavigationItemViewModel> NavigationItems { get; }
    public ICommand ToggleThemeCommand => toggleThemeCommand;
    public string CurrentProjectName => Workspace?.SelectedProject?.ProjectName ?? "尚未选择项目";
    public string CurrentDeviceName => Workspace?.SelectedDevice?.DisplayName ?? "尚未选择设备";
    public bool HasSelectedProject => Workspace?.SelectedProject != null;
    public int ProjectDeviceCount => Workspace?.Devices.Count ?? 0;
    public int SuccessfulConnectionTestCount => 0;
    public int PendingConnectionTestCount => ProjectDeviceCount;
    public int CollectionFailureCount => Collection.State == CollectionViewModelState.Failed ? 1 : 0;
    public string ReadOnlyProtectionStatus => "只读模式已启用";
    public bool IsWorkspaceSelectionEnabled => CanSynchronizeCollectionSelection();

    private void OnWorkspacePropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName == nameof(ProjectWorkspaceViewModel.SelectedProject))
        {
            OnPropertyChanged(nameof(CurrentProjectName));
            OnPropertyChanged(nameof(HasSelectedProject));
            if (Workspace?.SelectedProject != null && CanSynchronizeCollectionSelection())
            {
                Collection.SelectProject(Workspace.SelectedProject);
            }

            _ = EvidenceCenter.SelectProjectAsync(Workspace?.SelectedProject);
            _ = TaskHistory.SelectProjectAsync(Workspace?.SelectedProject);
        }

        if (eventArgs.PropertyName == nameof(ProjectWorkspaceViewModel.SelectedDevice))
        {
            OnPropertyChanged(nameof(CurrentDeviceName));
            if (CanSynchronizeCollectionSelection())
            {
                Collection.ClearDeviceSelection();
            }

            if (Workspace != null)
            {
                _ = Workspace.RefreshSelectedIdentificationAsync();
                if (Workspace.SelectedDevice != null)
                {
                    _ = Collection.RestorePendingIdentificationAsync(Workspace.SelectedDevice);
                }
            }

            if (CanSynchronizeCollectionSelection())
            {
                _ = SynchronizeSelectedDeviceAsync();
            }
        }

        if (eventArgs.PropertyName == nameof(ProjectWorkspaceViewModel.Devices))
        {
            OnPropertyChanged(nameof(ProjectDeviceCount));
            OnPropertyChanged(nameof(PendingConnectionTestCount));
        }
    }

    private void OnDeviceConnectionPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if ((eventArgs.PropertyName == nameof(DeviceConnectionViewModel.CurrentTrust)
                || eventArgs.PropertyName == nameof(DeviceConnectionViewModel.State))
            && Workspace?.SelectedDevice != null
            && DeviceConnection.CurrentTrust != null
            && DeviceConnection.State == DeviceConnectionViewModelState.Succeeded
            && CanSynchronizeCollectionSelection())
        {
            Collection.SelectDevice(new CollectionDeviceSelection(
                Workspace.SelectedDevice,
                ComponentCenter.IsSshAvailable,
                DeviceConnection.CurrentTrust));
        }
    }

    private async Task SynchronizeSelectedDeviceAsync()
    {
        var selectedDevice = Workspace?.SelectedDevice;
        await DeviceConnection.SelectDeviceAsync(selectedDevice);
        if (selectedDevice == null
            || !ReferenceEquals(selectedDevice, Workspace?.SelectedDevice)
            || DeviceConnection.State != DeviceConnectionViewModelState.Succeeded
            || DeviceConnection.CurrentTrust == null
            || !CanSynchronizeCollectionSelection())
        {
            return;
        }

        Collection.SelectDevice(new CollectionDeviceSelection(
            selectedDevice,
            ComponentCenter.IsSshAvailable,
            DeviceConnection.CurrentTrust));
    }

    private bool CanSynchronizeCollectionSelection()
    {
        return Collection.State != CollectionViewModelState.Running
            && Collection.State != CollectionViewModelState.Stopping;
    }

    private void OnCollectionPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName == nameof(CollectionViewModel.State))
        {
            OnPropertyChanged(nameof(CollectionFailureCount));
            OnPropertyChanged(nameof(IsWorkspaceSelectionEnabled));
            if (Collection.State == CollectionViewModelState.AwaitingConfirmation
                || Collection.State == CollectionViewModelState.DatabaseConfirmed
                || Collection.State == CollectionViewModelState.Completed
                || Collection.State == CollectionViewModelState.Stopped
                || Collection.State == CollectionViewModelState.Failed)
            {
                _ = EvidenceCenter.RefreshAsync();
            }

            if (Collection.State == CollectionViewModelState.AwaitingConfirmation
                || Collection.State == CollectionViewModelState.AwaitingDatabaseConfirmation
                || Collection.State == CollectionViewModelState.DatabaseConfirmed
                || Collection.State == CollectionViewModelState.Completed
                || Collection.State == CollectionViewModelState.Stopped
                || Collection.State == CollectionViewModelState.Failed)
            {
                _ = TaskHistory.RefreshAsync();
            }

            if (Workspace != null
                && (Collection.State == CollectionViewModelState.AwaitingConfirmation
                    || Collection.State == CollectionViewModelState.AwaitingDatabaseConfirmation
                    || Collection.State == CollectionViewModelState.DatabaseConfirmed
                    || Collection.State == CollectionViewModelState.Completed))
            {
                _ = Workspace.RefreshSelectedIdentificationAsync();
            }
        }
    }

    private void OnComponentCenterPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName == nameof(ComponentCenterViewModel.IsSshAvailable))
        {
            Collection.SetRequiredComponentAvailability(ComponentCenter.IsSshAvailable);
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private sealed class EmptyEvidenceCenterService : IEvidenceCenterService
    {
        public Task<EvidenceCenterSnapshot> LoadAsync(
            AssessmentTool.Core.Domain.ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new EvidenceCenterSnapshot(
                projectId,
                Array.Empty<EvidenceCenterItem>()));
        }

        public Task<EvidenceCenterSnapshot> VerifyAsync(
            AssessmentTool.Core.Domain.ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            return LoadAsync(projectId, cancellationToken);
        }
    }

    private sealed class EmptyCollectionTaskRepository : ICollectionTaskRepository
    {
        public Task<CollectionTaskRecord> CreateCollectionTaskAsync(
            CollectionTaskRecord task,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<CollectionTaskEventRecord> AppendCollectionTaskEventAsync(
            CollectionTaskId taskId,
            long expectedRevision,
            CollectionTaskState state,
            int? commandOrdinal,
            string eventCode,
            DateTimeOffset occurredAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<CollectionTaskRecord>> GetCollectionTasksAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<CollectionTaskRecord>>(Array.Empty<CollectionTaskRecord>());
        }

        public Task<IReadOnlyList<CollectionTaskEventRecord>> GetCollectionTaskEventsAsync(
            CollectionTaskId taskId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<CollectionTaskEventRecord>>(
                Array.Empty<CollectionTaskEventRecord>());
        }

        public Task<int> MarkInterruptedCollectionTasksAsync(
            DateTimeOffset interruptedAt,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }
    }
}

public sealed class NavigationItemViewModel
{
    private NavigationItemViewModel(string title, bool isAvailable)
    {
        Title = title;
        IsAvailable = isAvailable;
    }

    public string Title { get; }
    public bool IsAvailable { get; }
    public string StatusText => IsAvailable ? string.Empty : "后续版本";

    public static NavigationItemViewModel Available(string title)
    {
        return new NavigationItemViewModel(title, true);
    }

    public static NavigationItemViewModel Deferred(string title)
    {
        return new NavigationItemViewModel(title, false);
    }
}
