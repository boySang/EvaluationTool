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

namespace AssessmentTool.App.Services;

public sealed class CollectionWorkflowService : ICollectionWorkflowService
{
    private readonly BuiltinCommandPackCatalog commandCatalog;
    private readonly Func<ConnectionProfile, IRemoteSession> createSession;
    private readonly ICollectionEvidenceService evidenceService;

    public CollectionWorkflowService(
        ICredentialVault credentialVault,
        ICollectionEvidenceService evidenceService)
        : this(
            new BuiltinCommandPackCatalog(),
            new SshReadOnlySessionFactory(
                credentialVault ?? throw new ArgumentNullException(nameof(credentialVault))).Create,
            evidenceService)
    {
    }

    internal CollectionWorkflowService(
        BuiltinCommandPackCatalog commandCatalog,
        Func<ConnectionProfile, IRemoteSession> createSession,
        ICollectionEvidenceService evidenceService)
    {
        this.commandCatalog = commandCatalog ?? throw new ArgumentNullException(nameof(commandCatalog));
        this.createSession = createSession ?? throw new ArgumentNullException(nameof(createSession));
        this.evidenceService = evidenceService ?? throw new ArgumentNullException(nameof(evidenceService));
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
                && device.Category != TargetCategory.Server))
        {
            return UnsupportedTarget();
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

        var workflowStage = "加载通用 Linux 命令包";
        try
        {
            var fullPack = commandCatalog.LoadGenericLinux();
            var collectionPack = commandCatalog.CreateGenericLinuxCollectionPack(fullPack);
            workflowStage = "加载数据库发现命令包";
            var databaseDiscoveryPack = commandCatalog.LoadDatabaseHostDiscoveryLinux();
            workflowStage = "构建 SSH 连接资料";
            var profile = CreateProfile(device, trusted);
            workflowStage = "创建受控 SSH 会话";
            var session = createSession(profile);
            CollectionResult result;
            using (session as IDisposable)
            {
                var runner = new CollectionRunner(
                    session,
                    commandCatalog.SelectGenericLinuxIdentificationCommands(fullPack),
                    new[] { BuiltInIdentificationRules.LinuxOsReleaseId },
                    new DetectionEngine(),
                    new CommandMatcher(),
                    new CommandSafetyPolicy());
                result = await runner.RunAsync(
                    new CollectionRequest(collectionPack, request.ConfirmedCandidate),
                    progress,
                    cancellationToken);

                workflowStage = "保存 Linux 识别与采集证据";
                await SaveOutputsAsync(
                    request,
                    fullPack,
                    result.IdentificationOutputs.Concat(result.CommandOutputs));
                if (result.Outcome != CollectionOutcome.Completed)
                {
                    return MapResult(result);
                }

                workflowStage = "执行数据库主机只读发现";
                var discoveryResult = await new DatabaseDiscoveryRunner(
                    session,
                    new CommandSafetyPolicy(),
                    new HostDatabaseDiscovery()).RunAsync(
                        databaseDiscoveryPack,
                        progress,
                        cancellationToken);
                workflowStage = "保存数据库发现证据";
                await SaveOutputsAsync(request, databaseDiscoveryPack, discoveryResult.Outputs);
                workflowStage = "整理数据库发现结果";
                return MapDatabaseDiscovery(result, discoveryResult);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CollectionWorkflowResult.Stopped();
        }
        catch (Exception exception)
        {
            return CollectionWorkflowResult.Failed(new CollectionError(
                "只读采集任务失败",
                "连接、命令包或证据保存未完成",
                "检查设备连接、组件中心和证据目录后重试",
                BuildTechnicalDetails(workflowStage, exception)));
        }
    }

    private async Task SaveOutputsAsync(
        CollectionWorkflowRequest request,
        CommandPack fullPack,
        IEnumerable<CommandOutput> outputs)
    {
        var definitions = fullPack.Commands.ToDictionary(command => command.Id, StringComparer.Ordinal);
        foreach (var output in outputs)
        {
            CommandDefinition? command;
            if (!definitions.TryGetValue(output.CommandId, out command))
            {
                throw new InvalidOperationException("采集输出缺少对应的命令定义。");
            }

            await evidenceService.SaveAsync(
                request.Project,
                request.DeviceSelection.Device,
                fullPack.Version,
                command,
                output,
                CancellationToken.None);
        }
    }

    private static CollectionWorkflowResult MapResult(CollectionResult result)
    {
        switch (result.Outcome)
        {
            case CollectionOutcome.Completed:
                return CollectionWorkflowResult.Completed(
                    result.CommandOutputs.Select(output => new CompletedCollectionCommand(output.CommandId)));
            case CollectionOutcome.NeedsUserConfirmation:
                return CollectionWorkflowResult.RequiresConfirmation(
                    (result.Detection ?? throw new InvalidOperationException("识别确认结果缺少候选项。"))
                    .Candidates);
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
        DatabaseDiscoveryResult discovery)
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
        if (discovery.Candidates.Count == 0)
        {
            return CollectionWorkflowResult.Completed(completed);
        }

        return CollectionWorkflowResult.RequiresDatabaseConfirmation(
            discovery.Candidates.Select(candidate => candidate.RequireConfirmation()),
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
            "首个真实采集闭环仅开放 SSH Linux 服务器",
            "可以继续保存设备和测试登录；后续命令包验证完成后会逐步开放",
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
