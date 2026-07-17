using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

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
    {
        Workspace = workspace;
        Collection = collection ?? throw new ArgumentNullException(nameof(collection));
        ComponentCenter = componentCenter ?? throw new ArgumentNullException(nameof(componentCenter));
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
            NavigationItemViewModel.Deferred("命令库"),
            NavigationItemViewModel.Available("组件中心"),
            NavigationItemViewModel.Deferred("设置")
        });
        Collection.SetRequiredComponentAvailability(ComponentCenter.IsSshAvailable);
        Collection.PropertyChanged += OnCollectionPropertyChanged;
        ComponentCenter.PropertyChanged += OnComponentCenterPropertyChanged;
        if (Workspace != null)
        {
            Workspace.PropertyChanged += OnWorkspacePropertyChanged;
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ProjectWorkspaceViewModel? Workspace { get; }
    public CollectionViewModel Collection { get; }
    public ComponentCenterViewModel ComponentCenter { get; }
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

    private void OnWorkspacePropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName == nameof(ProjectWorkspaceViewModel.SelectedProject))
        {
            OnPropertyChanged(nameof(CurrentProjectName));
            OnPropertyChanged(nameof(HasSelectedProject));
        }

        if (eventArgs.PropertyName == nameof(ProjectWorkspaceViewModel.SelectedDevice))
        {
            OnPropertyChanged(nameof(CurrentDeviceName));
        }

        if (eventArgs.PropertyName == nameof(ProjectWorkspaceViewModel.Devices))
        {
            OnPropertyChanged(nameof(ProjectDeviceCount));
            OnPropertyChanged(nameof(PendingConnectionTestCount));
        }
    }

    private void OnCollectionPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName == nameof(CollectionViewModel.State))
        {
            OnPropertyChanged(nameof(CollectionFailureCount));
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
