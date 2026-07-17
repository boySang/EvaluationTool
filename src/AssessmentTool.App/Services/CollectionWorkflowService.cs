using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using AssessmentTool.Core.Security;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Sessions;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public sealed class CollectionWorkflowService : ICollectionWorkflowService
{
    private readonly BuiltinCommandPackCatalog commandCatalog;
    private readonly IReadOnlyList<IdentificationRule> identificationRules;
    private readonly Func<ConnectionProfile, IRemoteSession> createSession;
    private readonly ICollectionEvidenceService evidenceService;
    private readonly IDeviceIdentificationRepository? identificationRepository;
    private readonly IPendingDeviceIdentificationRepository? pendingIdentificationRepository;
    private readonly ICollectionTaskRepository? collectionTaskRepository;
    private readonly IHostSoftwareDiscoveryRepository? hostSoftwareDiscoveryRepository;
    private readonly ICommandPackReleaseService? commandPackReleaseService;

    public CollectionWorkflowService(
        ICredentialVault credentialVault,
        ICollectionEvidenceService evidenceService)
        : this(
            new BuiltinCommandPackCatalog(),
            new SshReadOnlySessionFactory(
                credentialVault ?? throw new ArgumentNullException(nameof(credentialVault))).Create,
            evidenceService,
            null)
    {
    }

    public CollectionWorkflowService(
        ICredentialVault credentialVault,
        ICollectionEvidenceService evidenceService,
        IDeviceIdentificationRepository identificationRepository)
        : this(credentialVault, evidenceService, identificationRepository, null)
    {
    }

    public CollectionWorkflowService(
        ICredentialVault credentialVault,
        ICollectionEvidenceService evidenceService,
        IDeviceIdentificationRepository identificationRepository,
        ICommandPackReleaseService? commandPackReleaseService)
        : this(
            new BuiltinCommandPackCatalog(),
            new SshReadOnlySessionFactory(
                credentialVault ?? throw new ArgumentNullException(nameof(credentialVault))).Create,
            evidenceService,
            identificationRepository ?? throw new ArgumentNullException(nameof(identificationRepository)),
            null,
            commandPackReleaseService)
    {
    }

    internal CollectionWorkflowService(
        BuiltinCommandPackCatalog commandCatalog,
        Func<ConnectionProfile, IRemoteSession> createSession,
        ICollectionEvidenceService evidenceService)
        : this(commandCatalog, createSession, evidenceService, null)
    {
    }

    internal CollectionWorkflowService(
        BuiltinCommandPackCatalog commandCatalog,
        Func<ConnectionProfile, IRemoteSession> createSession,
        ICollectionEvidenceService evidenceService,
        IDeviceIdentificationRepository? identificationRepository,
        IReadOnlyList<IdentificationRule>? identificationRules = null,
        ICommandPackReleaseService? commandPackReleaseService = null)
    {
        this.commandCatalog = commandCatalog ?? throw new ArgumentNullException(nameof(commandCatalog));
        this.createSession = createSession ?? throw new ArgumentNullException(nameof(createSession));
        this.evidenceService = evidenceService ?? throw new ArgumentNullException(nameof(evidenceService));
        this.identificationRepository = identificationRepository;
        pendingIdentificationRepository = identificationRepository as IPendingDeviceIdentificationRepository;
        collectionTaskRepository = identificationRepository as ICollectionTaskRepository;
        hostSoftwareDiscoveryRepository = identificationRepository as IHostSoftwareDiscoveryRepository;
        this.commandPackReleaseService = commandPackReleaseService;
        this.identificationRules = identificationRules ?? new[] { BuiltInIdentificationRules.LinuxOsReleaseId };
    }

    public async Task<CollectionWorkflowResult> RunAsync(
        CollectionWorkflowRequest request,
        IProgress<CollectionProgress> progress,
        CancellationToken cancellationToken)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (progress == null)
        {
            throw new ArgumentNullException(nameof(progress));
        }

        var device = request.DeviceSelection.Device;
        if (device.Protocol != ConnectionProtocol.Ssh
            || (device.Category != TargetCategory.Automatic
                && device.Category != TargetCategory.Server
                && device.Category != TargetCategory.NetworkDevice))
        {
            return UnsupportedTarget();
        }

        if (!IsAdapterCompatible(device.Category, request.AdapterId))
        {
            return CollectionWorkflowResult.Failed(new CollectionError(
                "采集适配器与设备类别不匹配",
                "当前设备类别不能使用所选厂商或系统适配器",
                device.Category == TargetCategory.NetworkDevice
                    ? "请在采集页明确选择与实际厂商一致且已经验证的网络设备适配器"
                    : "请改用通用 Linux 服务器适配器，或返回设备页修正设备类别",
                "CollectionAdapterTargetMismatch"));
        }

        if (!request.DeviceSelection.IsRequiredComponentAvailable)
        {
            return CollectionWorkflowResult.Failed(new CollectionError(
                "SSH 连接组件不可用",
                "可信 Plink 组件缺失、损坏或未通过完整性检查",
                "前往组件中心查看离线修复步骤后重新检测",
                "RequiredComponentUnavailable"));
        }

        var trusted = request.DeviceSelection.HostKeyTrust;
        if (!trusted.IsEligibleForAutomaticConnection)
        {
            return CollectionWorkflowResult.Failed(new CollectionError(
                "SSH 主机指纹尚未确认",
                "设备身份尚未完成人工核对",
                "返回设备页完成指纹确认和无命令登录测试",
                "HostKeyTrustNotEligible"));
        }

        var isHuaweiVrpWorkflow = request.AdapterId == CollectionAdapterId.HuaweiVrp;
        var workflowStage = isHuaweiVrpWorkflow ? "加载华为 VRP 命令包" : "加载通用 Linux 命令包";
        WorkflowExecutionObserver? executionObserver = null;
        try
        {
            var fullPack = isHuaweiVrpWorkflow
                ? commandCatalog.LoadHuaweiVrp()
                : commandCatalog.LoadGenericLinux();
            var collectionPack = isHuaweiVrpWorkflow
                ? await LoadHuaweiVrpProjectCollectionPackAsync(
                    request.Project.Id,
                    fullPack,
                    cancellationToken).ConfigureAwait(false)
                : await LoadProjectCollectionPackAsync(
                    request.Project.Id,
                    fullPack,
                    cancellationToken).ConfigureAwait(false);
            CommandPack? databaseDiscoveryPack = null;
            if (!isHuaweiVrpWorkflow)
            {
                workflowStage = "加载数据库发现命令包";
                databaseDiscoveryPack = commandCatalog.LoadDatabaseHostDiscoveryLinux();
            }
            executionObserver = new WorkflowExecutionObserver(
                this,
                request,
                fullPack,
                collectionPack,
                databaseDiscoveryPack,
                collectionTaskRepository,
                evidenceService);
            workflowStage = "构建 SSH 连接资料";
            var profile = CreateProfile(device, trusted);
            workflowStage = "创建受控 SSH 会话";
            var session = createSession(profile);
            CollectionResult result;
            using (session as IDisposable)
            {
                var runner = new CollectionRunner(
                    session,
                    isHuaweiVrpWorkflow
                        ? commandCatalog.SelectHuaweiVrpIdentificationCommands(fullPack)
                        : commandCatalog.SelectGenericLinuxIdentificationCommands(fullPack),
                    isHuaweiVrpWorkflow
                        ? new[] { BuiltInIdentificationRules.HuaweiVrp }
                        : identificationRules,
                    new DetectionEngine(),
                    new CommandMatcher(),
                    new CommandSafetyPolicy(),
                    executionObserver);
                result = await runner.RunAsync(
                    new CollectionRequest(collectionPack, request.ConfirmedCandidate),
                    progress,
                    cancellationToken);

                if (result.Outcome != CollectionOutcome.Completed)
                {
                    if (isHuaweiVrpWorkflow
                        && result.Outcome == CollectionOutcome.NeedsUserConfirmation
                        && (result.Detection == null || result.Detection.Candidates.Count == 0))
                    {
                        return CollectionWorkflowResult.Failed(new CollectionError(
                            "未识别为华为 VRP 网络设备",
                            "固定 display version 查询没有返回可由华为官方特征规则确认的结果",
                            "请核对设备厂商；H3C、Cisco、锐捷等设备不得选择华为 VRP 适配器",
                            "HuaweiVrpIdentityNotDetected"));
                    }

                    var identification = executionObserver.HasTask
                        ? IdentificationPersistenceResult.Empty
                        : await SaveIdentificationStateAsync(
                            device,
                            request.PendingIdentificationBatchId,
                            result.Detection,
                            result.Outcome == CollectionOutcome.NeedsUserConfirmation,
                            cancellationToken).ConfigureAwait(false);
                    await executionObserver.FinalizeAsync(
                        result.Outcome == CollectionOutcome.Stopped
                            ? CollectionTaskState.Stopped
                            : CollectionTaskState.Failed,
                        result.Outcome.ToString(),
                        CancellationToken.None).ConfigureAwait(false);
                    return MapResult(result, identification.PendingBatchId);
                }

                if (isHuaweiVrpWorkflow)
                {
                    await executionObserver.FinalizeAsync(
                        CollectionTaskState.Completed,
                        CollectionOutcome.Completed.ToString(),
                        CancellationToken.None).ConfigureAwait(false);
                    return MapResult(result, null);
                }

                workflowStage = "执行数据库主机只读发现";
                var discoveryResult = await new DatabaseDiscoveryRunner(
                    session,
                    new CommandSafetyPolicy(),
                    new HostDatabaseDiscovery(),
                    executionObserver).RunAsync(
                        databaseDiscoveryPack!,
                        progress,
                        cancellationToken);
                workflowStage = "保存数据库与中间件待确认结果";
                HostSoftwareDiscoveryBatchRecord? hostSoftwareBatch = null;
                if (discoveryResult.DatabaseCandidates.Count != 0
                    || discoveryResult.MiddlewareCandidates.Count != 0)
                {
                    if (hostSoftwareDiscoveryRepository == null || !executionObserver.HasTask)
                    {
                        throw new InvalidOperationException(
                            "主机软件发现持久化服务不可用，已阻止返回无法恢复的候选结果。");
                    }

                    var inputs = new HostSoftwareDiscoveryBatchBuilder().Build(
                        discoveryResult,
                        executionObserver.RawOutputSha256ByCommand);
                    hostSoftwareBatch = await hostSoftwareDiscoveryRepository
                        .AppendHostSoftwareDiscoveryBatchAsync(
                            request.Project.Id,
                            device.Id,
                            executionObserver.TaskId,
                            inputs,
                            "固定只读主机软件发现命令包 "
                                + databaseDiscoveryPack!.Id
                                + "@"
                                + databaseDiscoveryPack.Version,
                            DateTimeOffset.UtcNow,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                workflowStage = "整理数据库与中间件发现结果";
                await executionObserver.FinalizeAsync(
                    discoveryResult.Outcome == DatabaseDiscoveryOutcome.Completed
                        ? CollectionTaskState.Completed
                        : discoveryResult.Outcome == DatabaseDiscoveryOutcome.Stopped
                            ? CollectionTaskState.Stopped
                            : CollectionTaskState.Failed,
                    discoveryResult.Outcome.ToString(),
                    CancellationToken.None).ConfigureAwait(false);
                return MapDatabaseDiscovery(result, discoveryResult, hostSoftwareBatch);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (executionObserver != null)
            {
                await executionObserver.FinalizeAsync(
                    CollectionTaskState.Stopped,
                    "Cancelled",
                    CancellationToken.None).ConfigureAwait(false);
            }

            return CollectionWorkflowResult.Stopped();
        }
        catch (Exception exception)
        {
            if (executionObserver != null)
            {
                await executionObserver.TryFinalizeFailureAsync().ConfigureAwait(false);
            }

            return CollectionWorkflowResult.Failed(new CollectionError(
                "只读采集任务失败",
                "连接、命令包或证据保存未完成",
                "检查设备连接、组件中心和证据目录后重试",
                BuildTechnicalDetails(workflowStage, exception)));
        }
    }

    private static bool IsAdapterCompatible(
        TargetCategory category,
        CollectionAdapterId adapterId)
    {
        switch (adapterId)
        {
            case CollectionAdapterId.GenericLinux:
                return category == TargetCategory.Automatic
                    || category == TargetCategory.Server;
            case CollectionAdapterId.HuaweiVrp:
                return category == TargetCategory.NetworkDevice;
            default:
                return false;
        }
    }

    private async Task<CommandPack> LoadProjectCollectionPackAsync(
        ProjectId projectId,
        CommandPack builtinFullPack,
        CancellationToken cancellationToken)
    {
        if (commandPackReleaseService == null)
        {
            return commandCatalog.CreateGenericLinuxCollectionPack(builtinFullPack);
        }

        var selected = await commandPackReleaseService.LoadCurrentProjectPackAsync(
            projectId,
            builtinFullPack.Id,
            cancellationToken).ConfigureAwait(false);
        if (selected == null)
        {
            return commandCatalog.CreateGenericLinuxCollectionPack(builtinFullPack);
        }

        var fixedIdentificationIds = new HashSet<string>(
            commandCatalog.GenericLinuxIdentificationCommandIds,
            StringComparer.Ordinal);
        var collectionIds = selected.Commands
            .Where(command => !string.Equals(command.CheckItem, "IDENTIFY", StringComparison.Ordinal))
            .Select(command => command.Id)
            .ToArray();
        if (collectionIds.Length == 0)
        {
            throw new CommandPackException("项目锁定命令包不包含可执行的采集命令。");
        }

        if (collectionIds.Any(fixedIdentificationIds.Contains))
        {
            throw new CommandPackException("项目锁定命令包与固定识别命令标识冲突，已阻止执行。");
        }

        return selected.SelectCommands(collectionIds);
    }

    private async Task<CommandPack> LoadHuaweiVrpProjectCollectionPackAsync(
        ProjectId projectId,
        CommandPack builtinFullPack,
        CancellationToken cancellationToken)
    {
        if (commandPackReleaseService == null)
        {
            return commandCatalog.CreateHuaweiVrpCollectionPack(builtinFullPack);
        }

        var selected = await commandPackReleaseService.LoadCurrentProjectPackAsync(
            projectId,
            builtinFullPack.Id,
            cancellationToken).ConfigureAwait(false);
        if (selected == null)
        {
            return commandCatalog.CreateHuaweiVrpCollectionPack(builtinFullPack);
        }

        var fixedIdentificationIds = new HashSet<string>(
            commandCatalog.HuaweiVrpIdentificationCommandIds,
            StringComparer.Ordinal);
        var collectionIds = selected.Commands
            .Where(command => !string.Equals(command.CheckItem, "IDENTIFY", StringComparison.Ordinal))
            .Select(command => command.Id)
            .ToArray();
        if (collectionIds.Length == 0 || collectionIds.Any(fixedIdentificationIds.Contains))
        {
            throw new CommandPackException("项目锁定的华为 VRP 命令包缺少安全采集命令或与固定识别命令冲突。");
        }

        return selected.SelectCommands(collectionIds);
    }

    private async Task<IdentificationPersistenceResult> SaveIdentificationStateAsync(
        DeviceRecord device,
        Guid? previousPendingBatchId,
        DetectionResult? detection,
        bool requiresConfirmation,
        CancellationToken cancellationToken)
    {
        if (detection == null)
        {
            return IdentificationPersistenceResult.Empty;
        }

        if (requiresConfirmation || detection.RequiresUserConfirmation)
        {
            if (pendingIdentificationRepository == null)
            {
                throw new InvalidOperationException("待确认识别候选持久化服务不可用，已阻止继续。");
            }

            var batch = await pendingIdentificationRepository.AppendPendingDeviceIdentificationAsync(
                device.Id,
                detection.Candidates,
                previousPendingBatchId,
                DateTimeOffset.UtcNow,
                cancellationToken).ConfigureAwait(false);
            return new IdentificationPersistenceResult(batch.BatchId, null);
        }

        if (detection.Candidates.Count != 1)
        {
            return IdentificationPersistenceResult.Empty;
        }

        if (previousPendingBatchId.HasValue)
        {
            if (!detection.WasUserConfirmed)
            {
                throw new InvalidOperationException("待确认识别候选未通过当前结果重新校验，已阻止提交。");
            }

            if (pendingIdentificationRepository == null)
            {
                throw new InvalidOperationException("待确认识别候选处理服务不可用，已阻止继续。");
            }

            var completed = await pendingIdentificationRepository.CompletePendingDeviceIdentificationAsync(
                device.Id,
                previousPendingBatchId.Value,
                detection.Candidates[0],
                "测评人员在设备识别候选界面人工确认",
                DateTimeOffset.UtcNow,
                cancellationToken).ConfigureAwait(false);
            return new IdentificationPersistenceResult(null, completed);
        }

        if (identificationRepository != null)
        {
            var recorded = await identificationRepository.AppendDeviceIdentificationAsync(
                device.Id,
                detection.Candidates[0],
                detection.WasUserConfirmed,
                detection.WasUserConfirmed ? "测评人员在设备识别候选界面人工确认" : null,
                DateTimeOffset.UtcNow,
                cancellationToken).ConfigureAwait(false);
            return new IdentificationPersistenceResult(null, recorded);
        }

        return IdentificationPersistenceResult.Empty;
    }

    private sealed class IdentificationPersistenceResult
    {
        public static readonly IdentificationPersistenceResult Empty =
            new IdentificationPersistenceResult(null, null);

        public IdentificationPersistenceResult(
            Guid? pendingBatchId,
            DeviceIdentificationRecord? record)
        {
            PendingBatchId = pendingBatchId;
            Record = record;
        }

        public Guid? PendingBatchId { get; }
        public DeviceIdentificationRecord? Record { get; }
    }

    private sealed class WorkflowExecutionObserver : ICollectionExecutionObserver
    {
        private readonly CollectionWorkflowService owner;
        private readonly CollectionWorkflowRequest request;
        private readonly CommandPack identificationPack;
        private readonly CommandPack collectionPack;
        private readonly CommandPack? databaseDiscoveryPack;
        private readonly ICollectionTaskRepository? taskRepository;
        private readonly ICollectionEvidenceService evidenceService;
        private readonly Dictionary<string, CommandDefinition> identificationCommands;
        private readonly Dictionary<string, CommandDefinition> collectionCommands;
        private readonly Dictionary<string, CommandDefinition> databaseCommands;
        private readonly Dictionary<string, string> rawOutputSha256ByCommand =
            new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly List<string> completedBeforeTask = new List<string>();
        private readonly Dictionary<string, int> taskOrdinals = new Dictionary<string, int>(StringComparer.Ordinal);
        private CollectionTaskId taskId;
        private long eventRevision;
        private bool hasTask;
        private bool finalized;

        public WorkflowExecutionObserver(
            CollectionWorkflowService owner,
            CollectionWorkflowRequest request,
            CommandPack identificationPack,
            CommandPack collectionPack,
            CommandPack? databaseDiscoveryPack,
            ICollectionTaskRepository? taskRepository,
            ICollectionEvidenceService evidenceService)
        {
            this.owner = owner;
            this.request = request;
            this.identificationPack = identificationPack;
            this.collectionPack = collectionPack;
            this.databaseDiscoveryPack = databaseDiscoveryPack;
            this.taskRepository = taskRepository;
            this.evidenceService = evidenceService;
            identificationCommands = identificationPack.Commands
                .Where(command => string.Equals(command.CheckItem, "IDENTIFY", StringComparison.Ordinal))
                .ToDictionary(command => command.Id, StringComparer.Ordinal);
            collectionCommands = collectionPack.Commands.ToDictionary(command => command.Id, StringComparer.Ordinal);
            databaseCommands = databaseDiscoveryPack == null
                ? new Dictionary<string, CommandDefinition>(StringComparer.Ordinal)
                : databaseDiscoveryPack.Commands.ToDictionary(command => command.Id, StringComparer.Ordinal);
            var duplicateIds = identificationCommands.Keys
                .Concat(collectionCommands.Keys)
                .Concat(databaseCommands.Keys)
                .GroupBy(value => value, StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key)
                .ToArray();
            if (duplicateIds.Length != 0)
            {
                throw new CommandPackException("采集计划中的命令标识跨命令包重复，已阻止执行。");
            }
        }

        public bool HasTask => hasTask;
        public CollectionTaskId TaskId => HasTask
            ? taskId
            : throw new InvalidOperationException("采集任务总账尚未创建。");
        public IReadOnlyDictionary<string, string> RawOutputSha256ByCommand => rawOutputSha256ByCommand;

        public async Task OnPlanReadyAsync(
            DetectionResult detection,
            IReadOnlyList<CommandDefinition> commands,
            CancellationToken cancellationToken)
        {
            if (taskRepository == null)
            {
                throw new InvalidOperationException("采集任务总账服务不可用，已阻止执行远程采集命令。");
            }

            if (HasTask)
            {
                throw new InvalidOperationException("采集任务计划已创建，不能重复创建。");
            }

            var identification = await owner.SaveIdentificationStateAsync(
                request.DeviceSelection.Device,
                request.PendingIdentificationBatchId,
                detection,
                requiresConfirmation: false,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if (identification.Record == null)
            {
                throw new InvalidOperationException("设备身份尚未形成最终审计记录，已阻止创建采集任务。");
            }

            var selectedCommands = identificationCommands.Values
                .Select(command => new PackCommand(identificationPack, command))
                .Concat(commands.Select(command => new PackCommand(collectionPack, command)))
                .Concat(databaseDiscoveryPack == null
                    ? Enumerable.Empty<PackCommand>()
                    : databaseDiscoveryPack.Commands.Select(command =>
                        new PackCommand(databaseDiscoveryPack, command)))
                .ToArray();
            var validatedAt = DateTimeOffset.UtcNow;
            var safetyPolicy = new CommandSafetyPolicy();
            var snapshots = new List<CollectionTaskCommandSnapshot>(selectedCommands.Length);
            for (var ordinal = 0; ordinal < selectedCommands.Length; ordinal++)
            {
                var item = selectedCommands[ordinal];
                var safety = safetyPolicy.Validate(item.Command);
                if (!safety.Allowed)
                {
                    throw new InvalidOperationException("采集任务包含未通过只读安全复核的命令，已阻止创建。");
                }

                taskOrdinals.Add(item.Command.Id, ordinal);
                snapshots.Add(new CollectionTaskCommandSnapshot(
                    ordinal,
                    item.Pack.Id,
                    item.Pack.Version,
                    item.Pack.Sha256,
                    item.Command.Id,
                    item.Command.CommandText,
                    item.Command.CheckItem,
                    item.Command.ResultDescription,
                    item.Command.RiskLevel,
                    item.Command.IsOptional,
                    validatedAt));
            }

            var device = request.DeviceSelection.Device;
            var trust = request.DeviceSelection.HostKeyTrust;
            var task = new CollectionTaskRecord(
                CollectionTaskId.New(),
                request.Project.Id,
                device.Id,
                identification.Record.Revision,
                device.Protocol,
                device.Host,
                device.Port,
                device.UserName,
                device.AuthenticationMethod,
                trust.Algorithm ?? throw new InvalidOperationException("采集任务缺少已固定的主机密钥算法。"),
                trust.Fingerprint ?? throw new InvalidOperationException("采集任务缺少已固定的主机指纹。"),
                snapshots,
                validatedAt);
            await taskRepository.CreateCollectionTaskAsync(task, cancellationToken).ConfigureAwait(false);
            taskId = task.Id;
            hasTask = true;
            var running = await taskRepository.AppendCollectionTaskEventAsync(
                taskId,
                1,
                CollectionTaskState.Running,
                null,
                "ExecutionStarted",
                DateTimeOffset.UtcNow,
                cancellationToken).ConfigureAwait(false);
            eventRevision = running.Revision;

            foreach (var commandId in completedBeforeTask)
            {
                await AppendCommandEventAsync(commandId, cancellationToken).ConfigureAwait(false);
            }

            completedBeforeTask.Clear();
        }

        public async Task OnCommandCompletedAsync(
            CommandDefinition command,
            CommandOutput output,
            CancellationToken cancellationToken)
        {
            CommandPack pack;
            if (identificationCommands.ContainsKey(command.Id))
            {
                pack = identificationPack;
            }
            else if (collectionCommands.ContainsKey(command.Id))
            {
                pack = collectionPack;
            }
            else if (databaseCommands.ContainsKey(command.Id))
            {
                pack = databaseDiscoveryPack
                    ?? throw new InvalidOperationException("数据库发现命令缺少命令包归属。");
            }
            else
            {
                throw new InvalidOperationException("采集输出缺少受信任命令包归属。");
            }

            var saved = await evidenceService.SaveAsync(
                request.Project,
                request.DeviceSelection.Device,
                pack.Version,
                command,
                output,
                cancellationToken).ConfigureAwait(false);
            var rawOutputSha256 = saved?.Execution.RawOutputSha256;
            if (rawOutputSha256 == null
                || rawOutputSha256.Trim().Length == 0
                || rawOutputSha256ByCommand.ContainsKey(command.Id))
            {
                throw new InvalidOperationException(
                    "采集命令缺少唯一的已保存原始输出完整性校验值。");
            }

            rawOutputSha256ByCommand.Add(command.Id, rawOutputSha256);

            if (HasTask)
            {
                await AppendCommandEventAsync(command.Id, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                completedBeforeTask.Add(command.Id);
            }
        }

        public async Task FinalizeAsync(
            CollectionTaskState state,
            string eventCode,
            CancellationToken cancellationToken)
        {
            if (!HasTask || finalized)
            {
                return;
            }

            var recorded = await taskRepository!.AppendCollectionTaskEventAsync(
                taskId,
                eventRevision,
                state,
                null,
                eventCode,
                DateTimeOffset.UtcNow,
                cancellationToken).ConfigureAwait(false);
            eventRevision = recorded.Revision;
            finalized = true;
        }

        public async Task TryFinalizeFailureAsync()
        {
            try
            {
                await FinalizeAsync(
                    CollectionTaskState.Failed,
                    "UnexpectedFailure",
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private async Task AppendCommandEventAsync(
            string commandId,
            CancellationToken cancellationToken)
        {
            if (!taskOrdinals.TryGetValue(commandId, out var ordinal))
            {
                throw new InvalidOperationException("完成的命令不属于已锁定任务计划。");
            }

            var recorded = await taskRepository!.AppendCollectionTaskEventAsync(
                taskId,
                eventRevision,
                CollectionTaskState.Running,
                ordinal,
                "CommandEvidenceCommitted",
                DateTimeOffset.UtcNow,
                cancellationToken).ConfigureAwait(false);
            eventRevision = recorded.Revision;
        }

        private sealed class PackCommand
        {
            public PackCommand(CommandPack pack, CommandDefinition command)
            {
                Pack = pack;
                Command = command;
            }

            public CommandPack Pack { get; }
            public CommandDefinition Command { get; }
        }
    }

    private static CollectionWorkflowResult MapResult(CollectionResult result, Guid? pendingBatchId)
    {
        switch (result.Outcome)
        {
            case CollectionOutcome.Completed:
                return CollectionWorkflowResult.Completed(
                    result.CommandOutputs.Select(output => new CompletedCollectionCommand(output.CommandId)));
            case CollectionOutcome.NeedsUserConfirmation:
                return CollectionWorkflowResult.RequiresConfirmation(
                    (result.Detection ?? throw new InvalidOperationException("识别确认结果缺少候选项。"))
                    .Candidates,
                    pendingBatchId ?? throw new InvalidOperationException("识别确认结果缺少持久化批次。"));
            case CollectionOutcome.Stopped:
                return CollectionWorkflowResult.Stopped();
            default:
                return CollectionWorkflowResult.Failed(new CollectionError(
                    "只读采集未完成",
                    result.Message,
                    "检查识别结果、只读命令兼容性和连接权限后重试",
                    result.Outcome.ToString()));
        }
    }

    private static CollectionWorkflowResult MapDatabaseDiscovery(
        CollectionResult collection,
        DatabaseDiscoveryResult discovery,
        HostSoftwareDiscoveryBatchRecord? hostSoftwareBatch)
    {
        if (discovery.Outcome == DatabaseDiscoveryOutcome.Stopped)
        {
            return CollectionWorkflowResult.Stopped();
        }

        if (discovery.Outcome != DatabaseDiscoveryOutcome.Completed)
        {
            return CollectionWorkflowResult.Failed(new CollectionError(
                "数据库主机只读发现未完成",
                discovery.Message,
                "检查只读账户是否可读取进程与 systemd 服务；Docker 或 Podman 未安装不影响其他发现",
                discovery.Outcome.ToString()));
        }

        var completed = collection.CommandOutputs
            .Concat(discovery.Outputs.Where(output => output.Outcome == RemoteExecutionOutcome.Succeeded))
            .Select(output => new CompletedCollectionCommand(output.CommandId))
            .ToArray();
        if (discovery.DatabaseCandidates.Count == 0
            && discovery.MiddlewareCandidates.Count == 0)
        {
            return CollectionWorkflowResult.Completed(completed);
        }

        return CollectionWorkflowResult.RequiresHostSoftwareConfirmation(
            discovery.DatabaseCandidates.Select(candidate => candidate.RequireConfirmation()),
            discovery.MiddlewareCandidates,
            hostSoftwareBatch
                ?? throw new InvalidOperationException("主机软件候选缺少可恢复的持久化批次。"),
            completed);
    }

    private static ConnectionProfile CreateProfile(DeviceRecord device, HostKeyTrust trust)
    {
        return new ConnectionProfile(
            device.DisplayName,
            device.Host,
            device.Port,
            ConnectionProtocol.Ssh,
            new SshConnectionOptions(
                trust.Endpoint,
                device.UserName,
                device.AuthenticationMethod,
                device.CredentialReference,
                device.PrivateKeyReference,
                trust));
    }

    private static CollectionWorkflowResult UnsupportedTarget()
    {
        return CollectionWorkflowResult.Failed(new CollectionError(
            "当前体验版尚未启用该设备的自动采集",
            "当前开放 SSH Linux 服务器和经人工确认的华为 VRP 网络设备",
            "可以继续保存设备和测试登录；其他厂商命令包验证完成后会逐步开放",
            "UnsupportedCollectionTarget"));
    }

    private static string BuildTechnicalDetails(string workflowStage, Exception exception)
    {
        var argument = exception as ArgumentException;
        var parameterName = argument?.ParamName;
        return workflowStage + ":" + exception.GetType().Name
            + (string.IsNullOrWhiteSpace(parameterName) ? string.Empty : ":" + parameterName);
    }
}
