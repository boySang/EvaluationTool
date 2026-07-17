using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class CollectionTaskHistoryViewModelTests
{
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task Selecting_project_loads_tasks_with_their_latest_events()
    {
        var project = CreateProject("项目甲");
        var olderTask = CreateTask(project.Id, DateTimeOffset.UtcNow.AddHours(-2), "192.0.2.10");
        var newerTask = CreateTask(project.Id, DateTimeOffset.UtcNow.AddHours(-1), "192.0.2.20");
        var repository = new FakeCollectionTaskRepository(new[] { olderTask, newerTask });
        repository.Events[olderTask.Id] = new[]
        {
            CreateEvent(olderTask.Id, 1, CollectionTaskState.Ready, "Created", olderTask.CreatedAt),
            CreateEvent(olderTask.Id, 2, CollectionTaskState.Completed, "Completed", olderTask.CreatedAt.AddMinutes(3))
        };
        repository.Events[newerTask.Id] = new[]
        {
            CreateEvent(newerTask.Id, 2, CollectionTaskState.Running, "CommandEvidenceCommitted", newerTask.CreatedAt.AddMinutes(2)),
            CreateEvent(newerTask.Id, 1, CollectionTaskState.Ready, "Created", newerTask.CreatedAt)
        };
        var viewModel = new CollectionTaskHistoryViewModel(repository);

        await viewModel.SelectProjectAsync(project);

        Assert.Equal(CollectionTaskHistoryViewModelState.Ready, viewModel.State);
        Assert.True(viewModel.HasItems);
        Assert.Equal(newerTask.Id, viewModel.Items[0].TaskId);
        Assert.Equal(CollectionTaskState.Running, viewModel.Items[0].State);
        Assert.Equal("正在采集", viewModel.Items[0].StatusText);
        Assert.Equal(CollectionTaskState.Completed, viewModel.Items[1].State);
        Assert.Equal(project.Id, Assert.Single(repository.RequestedProjects));
        Assert.Equal(2, repository.RequestedTaskEvents.Count);
        Assert.True(viewModel.CanRefresh);
        Assert.Contains("2 条", viewModel.StatusMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Interrupted_task_is_explained_but_never_automatically_recovered()
    {
        var project = CreateProject("项目甲");
        var task = CreateTask(project.Id, DateTimeOffset.UtcNow, "192.0.2.30");
        var repository = new FakeCollectionTaskRepository(new[] { task });
        repository.Events[task.Id] = new[]
        {
            CreateEvent(task.Id, 1, CollectionTaskState.Ready, "Created", task.CreatedAt),
            CreateEvent(task.Id, 2, CollectionTaskState.Running, "Started", task.CreatedAt.AddSeconds(1)),
            CreateEvent(task.Id, 3, CollectionTaskState.Interrupted, "ApplicationRestarted", task.CreatedAt.AddMinutes(1))
        };
        var viewModel = new CollectionTaskHistoryViewModel(repository);

        await viewModel.SelectProjectAsync(project);

        var item = Assert.Single(viewModel.Items);
        Assert.True(item.IsInterrupted);
        Assert.Equal("上次采集异常中断", item.StatusText);
        Assert.Contains("不会自动恢复", item.StatusDescription, StringComparison.Ordinal);
        Assert.Equal(0, repository.MarkInterruptedCalls);
        Assert.Equal(0, repository.AppendedEventCalls);
    }

    [Fact]
    public async Task Empty_project_exposes_non_technical_empty_state()
    {
        var project = CreateProject("空项目");
        var viewModel = new CollectionTaskHistoryViewModel(
            new FakeCollectionTaskRepository(Array.Empty<CollectionTaskRecord>()));

        await viewModel.SelectProjectAsync(project);

        Assert.Equal(CollectionTaskHistoryViewModelState.Empty, viewModel.State);
        Assert.Empty(viewModel.Items);
        Assert.False(viewModel.HasItems);
        Assert.Contains("还没有采集任务", viewModel.StatusMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Loading_is_single_flight_and_exposes_a_read_only_binding_list()
    {
        var project = CreateProject("项目甲");
        var pending = new TaskCompletionSource<IReadOnlyList<CollectionTaskRecord>>();
        var repository = new FakeCollectionTaskRepository(pending.Task);
        var viewModel = new CollectionTaskHistoryViewModel(repository);

        var firstLoad = viewModel.SelectProjectAsync(project);
        var secondLoad = viewModel.RefreshAsync();

        Assert.Same(firstLoad, secondLoad);
        Assert.Equal(CollectionTaskHistoryViewModelState.Loading, viewModel.State);
        Assert.False(viewModel.CanRefresh);
        Assert.Single(repository.RequestedProjects);
        pending.SetResult(Array.Empty<CollectionTaskRecord>());
        await firstLoad;

        var bindingList = Assert.IsAssignableFrom<IList<CollectionTaskHistoryItem>>(viewModel.Items);
        Assert.True(bindingList.IsReadOnly);
        Assert.Equal(CollectionTaskHistoryViewModelState.Empty, viewModel.State);
    }

    [Fact]
    public async Task Selecting_no_project_clears_history_without_querying_repository()
    {
        var project = CreateProject("项目甲");
        var task = CreateTask(project.Id, DateTimeOffset.UtcNow, "192.0.2.40");
        var repository = new FakeCollectionTaskRepository(new[] { task });
        var viewModel = new CollectionTaskHistoryViewModel(repository);
        await viewModel.SelectProjectAsync(project);

        await viewModel.SelectProjectAsync(null);

        Assert.Null(viewModel.SelectedProject);
        Assert.Empty(viewModel.Items);
        Assert.Equal(CollectionTaskHistoryViewModelState.NoProject, viewModel.State);
        Assert.False(viewModel.CanRefresh);
        Assert.Single(repository.RequestedProjects);
    }

    [Fact]
    public async Task Failure_is_safe_and_actionable_for_non_technical_users()
    {
        var project = CreateProject("项目甲");
        var repository = new FakeCollectionTaskRepository(
            Task.FromException<IReadOnlyList<CollectionTaskRecord>>(
                new InvalidOperationException(@"secret C:\customer\tasks.db")));
        var viewModel = new CollectionTaskHistoryViewModel(repository);

        await viewModel.SelectProjectAsync(project);

        Assert.Equal(CollectionTaskHistoryViewModelState.Failed, viewModel.State);
        Assert.Equal("采集任务历史加载失败", viewModel.WhatHappened);
        Assert.Contains("数据库", viewModel.PossibleCause, StringComparison.Ordinal);
        Assert.Contains("刷新", viewModel.HowToFix, StringComparison.Ordinal);
        Assert.Equal(nameof(InvalidOperationException), viewModel.TechnicalDetails);
        Assert.True(viewModel.CanRefresh);
        var visibleText = string.Join(" ", viewModel.WhatHappened, viewModel.PossibleCause,
            viewModel.HowToFix, viewModel.TechnicalDetails, viewModel.StatusMessage);
        Assert.DoesNotContain("secret", visibleText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("customer", visibleText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Late_result_from_previous_project_cannot_replace_current_history()
    {
        var firstProject = CreateProject("项目甲");
        var secondProject = CreateProject("项目乙");
        var firstTask = CreateTask(firstProject.Id, DateTimeOffset.UtcNow, "192.0.2.50");
        var secondTask = CreateTask(secondProject.Id, DateTimeOffset.UtcNow, "192.0.2.60");
        var firstLoad = new TaskCompletionSource<IReadOnlyList<CollectionTaskRecord>>();
        var repository = new FakeCollectionTaskRepository(projectId =>
            projectId.Equals(firstProject.Id)
                ? firstLoad.Task
                : Task.FromResult<IReadOnlyList<CollectionTaskRecord>>(new[] { secondTask }));
        var viewModel = new CollectionTaskHistoryViewModel(repository);

        var staleLoad = viewModel.SelectProjectAsync(firstProject);
        await viewModel.SelectProjectAsync(secondProject);
        firstLoad.SetResult(new[] { firstTask });
        await staleLoad;

        Assert.Same(secondProject, viewModel.SelectedProject);
        Assert.Equal(secondTask.Id, Assert.Single(viewModel.Items).TaskId);
    }

    private static ProjectRecord CreateProject(string name)
    {
        return new ProjectRecord(ProjectId.New(), "测试客户", name, @"C:\Evidence", DateTimeOffset.UtcNow);
    }

    private static CollectionTaskRecord CreateTask(ProjectId projectId, DateTimeOffset createdAt, string host)
    {
        return new CollectionTaskRecord(
            CollectionTaskId.New(),
            projectId,
            DeviceId.New(),
            1,
            ConnectionProtocol.Ssh,
            host,
            22,
            "audit-user",
            SshAuthenticationMethod.Password,
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:history-test",
            new[]
            {
                new CollectionTaskCommandSnapshot(
                    0,
                    "generic-linux",
                    "1.0.0",
                    Hash,
                    "hostname",
                    "hostname",
                    "1.1.1",
                    "读取主机名",
                    CommandRiskLevel.Low,
                    false,
                    createdAt)
            },
            createdAt);
    }

    private static CollectionTaskEventRecord CreateEvent(
        CollectionTaskId taskId,
        long revision,
        CollectionTaskState state,
        string eventCode,
        DateTimeOffset occurredAt)
    {
        return new CollectionTaskEventRecord(taskId, revision, state, null, eventCode, occurredAt);
    }

    private sealed class FakeCollectionTaskRepository : ICollectionTaskRepository
    {
        private readonly Func<ProjectId, Task<IReadOnlyList<CollectionTaskRecord>>> loadTasks;

        public FakeCollectionTaskRepository(IEnumerable<CollectionTaskRecord> tasks)
            : this(_ => Task.FromResult<IReadOnlyList<CollectionTaskRecord>>(tasks.ToArray()))
        {
        }

        public FakeCollectionTaskRepository(Task<IReadOnlyList<CollectionTaskRecord>> tasks)
            : this(_ => tasks)
        {
        }

        public FakeCollectionTaskRepository(Func<ProjectId, Task<IReadOnlyList<CollectionTaskRecord>>> loadTasks)
        {
            this.loadTasks = loadTasks;
        }

        public Dictionary<CollectionTaskId, IReadOnlyList<CollectionTaskEventRecord>> Events { get; } =
            new Dictionary<CollectionTaskId, IReadOnlyList<CollectionTaskEventRecord>>();
        public List<ProjectId> RequestedProjects { get; } = new List<ProjectId>();
        public List<CollectionTaskId> RequestedTaskEvents { get; } = new List<CollectionTaskId>();
        public int MarkInterruptedCalls { get; private set; }
        public int AppendedEventCalls { get; private set; }

        public Task<IReadOnlyList<CollectionTaskRecord>> GetCollectionTasksAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            RequestedProjects.Add(projectId);
            return loadTasks(projectId);
        }

        public Task<IReadOnlyList<CollectionTaskEventRecord>> GetCollectionTaskEventsAsync(
            CollectionTaskId taskId,
            CancellationToken cancellationToken = default)
        {
            RequestedTaskEvents.Add(taskId);
            Events.TryGetValue(taskId, out var events);
            return Task.FromResult(events ?? (IReadOnlyList<CollectionTaskEventRecord>)Array.Empty<CollectionTaskEventRecord>());
        }

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
            AppendedEventCalls++;
            throw new NotSupportedException();
        }

        public Task<int> MarkInterruptedCollectionTasksAsync(
            DateTimeOffset interruptedAt,
            CancellationToken cancellationToken = default)
        {
            MarkInterruptedCalls++;
            return Task.FromResult(0);
        }
    }
}
