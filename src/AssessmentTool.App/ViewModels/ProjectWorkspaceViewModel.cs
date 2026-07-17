using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.ViewModels;

public enum ProjectWorkspaceState
{
    Uninitialized,
    Loading,
    Ready,
    CreatingProject,
    AddingDevice,
    Failed
}

public sealed class ProjectWorkspaceViewModel : INotifyPropertyChanged
{
    private readonly IProjectWorkspaceService service;
    private IReadOnlyList<ProjectRecord> projects = Array.Empty<ProjectRecord>();
    private IReadOnlyList<DeviceRecord> devices = Array.Empty<DeviceRecord>();
    private ProjectRecord? selectedProject;
    private DeviceRecord? selectedDevice;
    private ProjectWorkspaceState state = ProjectWorkspaceState.Uninitialized;
    private bool exclusiveOperation;
    private int projectLoadGeneration;
    private string customerName = string.Empty;
    private string projectName = string.Empty;
    private string evidenceRoot = string.Empty;
    private string deviceDisplayName = string.Empty;
    private string deviceHost = string.Empty;
    private string devicePortText = "22";
    private string deviceUserName = string.Empty;
    private TargetCategory deviceCategory = TargetCategory.Automatic;
    private string whatHappened = string.Empty;
    private string possibleCause = string.Empty;
    private string howToFix = string.Empty;
    private string technicalDetails = string.Empty;

    public ProjectWorkspaceViewModel(IProjectWorkspaceService service)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<ProjectRecord> Projects => projects;
    public IReadOnlyList<DeviceRecord> Devices => devices;
    public ProjectWorkspaceState State => state;

    public ProjectRecord? SelectedProject => selectedProject;

    public DeviceRecord? SelectedDevice
    {
        get => selectedDevice;
        set
        {
            if (ReferenceEquals(selectedDevice, value))
            {
                return;
            }

            if (value != null && (selectedProject == null || !value.ProjectId.Equals(selectedProject.Id)))
            {
                throw new ArgumentException("只能选择当前项目中的设备。", nameof(value));
            }

            selectedDevice = value;
            OnPropertyChanged();
        }
    }

    public string CustomerName { get => customerName; set => SetText(ref customerName, value); }
    public string ProjectName { get => projectName; set => SetText(ref projectName, value); }
    public string EvidenceRoot { get => evidenceRoot; set => SetText(ref evidenceRoot, value); }
    public string DeviceDisplayName { get => deviceDisplayName; set => SetText(ref deviceDisplayName, value); }
    public string DeviceHost { get => deviceHost; set => SetText(ref deviceHost, value); }
    public string DevicePortText { get => devicePortText; set => SetText(ref devicePortText, value); }
    public string DeviceUserName { get => deviceUserName; set => SetText(ref deviceUserName, value); }
    public TargetCategory DeviceCategory
    {
        get => deviceCategory;
        set
        {
            if (deviceCategory == value)
            {
                return;
            }

            deviceCategory = value;
            OnPropertyChanged();
        }
    }
    public string WhatHappened => whatHappened;
    public string PossibleCause => possibleCause;
    public string HowToFix => howToFix;
    public string TechnicalDetails => technicalDetails;

    public async Task InitializeAsync()
    {
        if (!TryBeginExclusive(ProjectWorkspaceState.Loading))
        {
            return;
        }

        try
        {
            await service.InitializeAsync();
            SetProjects(await service.GetProjectsAsync());
            SetState(ProjectWorkspaceState.Ready);
        }
        catch (Exception exception)
        {
            SetFailure("项目数据初始化失败", "本地数据库或文件权限异常", "重新启动软件；如仍失败，请检查组件和本地数据目录权限。", exception);
        }
        finally
        {
            exclusiveOperation = false;
        }
    }

    public async Task CreateProjectAsync()
    {
        if (!TryBeginExclusive(ProjectWorkspaceState.CreatingProject))
        {
            return;
        }

        try
        {
            var createdId = await service.CreateProjectAsync(CustomerName, ProjectName, EvidenceRoot);
            var refreshed = await service.GetProjectsAsync();
            SetProjects(refreshed);
            var created = refreshed.Single(project => project.Id.Equals(createdId));
            await SelectProjectCoreAsync(created, unchecked(++projectLoadGeneration));
        }
        catch (Exception exception)
        {
            SetFailure("项目创建失败", "项目资料或本地数据库不可用", "检查客户名称、项目名称和证据目录后重试。", exception);
        }
        finally
        {
            exclusiveOperation = false;
        }
    }

    public Task SelectProjectAsync(ProjectRecord project)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        return exclusiveOperation
            ? Task.CompletedTask
            : SelectProjectCoreAsync(project, unchecked(++projectLoadGeneration));
    }

    public async Task AddDeviceAsync(char[] password)
    {
        if (!TryBeginExclusive(ProjectWorkspaceState.AddingDevice))
        {
            Clear(password);
            return;
        }

        try
        {
            if (selectedProject == null)
            {
                throw new InvalidOperationException("请先选择项目后再保存设备。");
            }

            if (!int.TryParse(DevicePortText, out var port))
            {
                throw new ArgumentException("请输入 1 到 65535 之间的连接端口。", nameof(DevicePortText));
            }

            var createdId = await service.AddSshDeviceAsync(
                selectedProject.Id,
                DeviceDisplayName,
                DeviceHost,
                port,
                DeviceUserName,
                DeviceCategory,
                password);
            var refreshed = await service.GetDevicesAsync(selectedProject.Id);
            SetDevices(refreshed);
            SelectedDevice = refreshed.Single(device => device.Id.Equals(createdId));
            SetState(ProjectWorkspaceState.Ready);
        }
        catch (Exception exception)
        {
            SetFailure("设备保存失败", "连接资料、凭据保护或本地数据库异常", "检查设备信息和本机数据目录后重试。", exception);
        }
        finally
        {
            Clear(password);
            exclusiveOperation = false;
        }
    }

    private async Task SelectProjectCoreAsync(ProjectRecord project, int generation)
    {
        selectedProject = project;
        OnPropertyChanged(nameof(SelectedProject));
        SelectedDevice = null;
        SetDevices(Array.Empty<DeviceRecord>());
        SetState(ProjectWorkspaceState.Loading);
        try
        {
            var loaded = await service.GetDevicesAsync(project.Id);
            if (generation != projectLoadGeneration || !ReferenceEquals(selectedProject, project))
            {
                return;
            }

            SetDevices(loaded);
            SetState(ProjectWorkspaceState.Ready);
        }
        catch (Exception exception)
        {
            if (generation == projectLoadGeneration && ReferenceEquals(selectedProject, project))
            {
                SetFailure("设备列表加载失败", "本地项目数据库不可用", "重新选择项目或重新启动软件后重试。", exception);
            }
        }
    }

    private bool TryBeginExclusive(ProjectWorkspaceState nextState)
    {
        if (exclusiveOperation)
        {
            return false;
        }

        exclusiveOperation = true;
        ClearError();
        SetState(nextState);
        return true;
    }

    private void SetProjects(IEnumerable<ProjectRecord> value)
    {
        projects = new ReadOnlyCollection<ProjectRecord>(value.ToArray());
        OnPropertyChanged(nameof(Projects));
    }

    private void SetDevices(IEnumerable<DeviceRecord> value)
    {
        devices = new ReadOnlyCollection<DeviceRecord>(value.ToArray());
        OnPropertyChanged(nameof(Devices));
    }

    private void SetState(ProjectWorkspaceState value)
    {
        state = value;
        OnPropertyChanged(nameof(State));
    }

    private void SetFailure(string summary, string cause, string action, Exception exception)
    {
        whatHappened = summary;
        possibleCause = cause;
        howToFix = action;
        technicalDetails = exception.GetType().Name;
        OnPropertyChanged(nameof(WhatHappened));
        OnPropertyChanged(nameof(PossibleCause));
        OnPropertyChanged(nameof(HowToFix));
        OnPropertyChanged(nameof(TechnicalDetails));
        SetState(ProjectWorkspaceState.Failed);
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

    private void SetText(ref string field, string? value, [CallerMemberName] string? propertyName = null)
    {
        field = value ?? string.Empty;
        OnPropertyChanged(propertyName);
    }

    private static void Clear(char[]? value)
    {
        if (value != null)
        {
            Array.Clear(value, 0, value.Length);
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
