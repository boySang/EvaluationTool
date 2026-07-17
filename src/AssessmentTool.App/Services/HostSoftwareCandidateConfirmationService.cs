using System;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public interface IHostSoftwareCandidateConfirmationService
{
    Task<HostSoftwareCandidateDecisionRecord> ConfirmAsync(
        HostSoftwareDiscoveryCandidateRecord candidate,
        CancellationToken cancellationToken = default);

    Task<HostSoftwareCandidateDecisionRecord> RejectAsync(
        HostSoftwareDiscoveryCandidateRecord candidate,
        string reason,
        CancellationToken cancellationToken = default);
}

public interface ICurrentWindowsUserProvider
{
    string GetCurrentUserName();
}

public sealed class CurrentWindowsUserProvider : ICurrentWindowsUserProvider
{
    public string GetCurrentUserName()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            return identity.Name;
        }
    }
}

public sealed class HostSoftwareCandidateConfirmationService : IHostSoftwareCandidateConfirmationService
{
    private const string ManualDecisionSource = "测评人员在主机软件候选界面人工确认";
    private readonly IHostSoftwareDiscoveryRepository repository;
    private readonly ICurrentWindowsUserProvider currentWindowsUserProvider;
    private readonly Func<DateTimeOffset> utcNow;

    public HostSoftwareCandidateConfirmationService(IHostSoftwareDiscoveryRepository repository)
        : this(repository, new CurrentWindowsUserProvider(), () => DateTimeOffset.UtcNow)
    {
    }

    public HostSoftwareCandidateConfirmationService(
        IHostSoftwareDiscoveryRepository repository,
        ICurrentWindowsUserProvider currentWindowsUserProvider,
        Func<DateTimeOffset>? utcNow = null)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.currentWindowsUserProvider = currentWindowsUserProvider
            ?? throw new ArgumentNullException(nameof(currentWindowsUserProvider));
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public Task<HostSoftwareCandidateDecisionRecord> ConfirmAsync(
        HostSoftwareDiscoveryCandidateRecord candidate,
        CancellationToken cancellationToken = default)
    {
        return RecordDecisionAsync(
            candidate,
            HostSoftwareCandidateDecision.Confirmed,
            null,
            cancellationToken);
    }

    public Task<HostSoftwareCandidateDecisionRecord> RejectAsync(
        HostSoftwareDiscoveryCandidateRecord candidate,
        string reason,
        CancellationToken cancellationToken = default)
    {
        return RecordDecisionAsync(
            candidate,
            HostSoftwareCandidateDecision.Rejected,
            reason,
            cancellationToken);
    }

    internal Task<HostSoftwareCandidateDecisionRecord> RecordDecisionAsync(
        HostSoftwareDiscoveryCandidateRecord candidate,
        HostSoftwareCandidateDecision decision,
        string? reason,
        CancellationToken cancellationToken = default)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        if (decision != HostSoftwareCandidateDecision.Confirmed
            && decision != HostSoftwareCandidateDecision.Rejected)
        {
            throw new ArgumentOutOfRangeException(
                nameof(decision),
                decision,
                "Only manual confirmation or rejection decisions can be submitted by this service.");
        }

        string? normalizedReason = null;
        if (decision == HostSoftwareCandidateDecision.Rejected)
        {
            normalizedReason = RequireAuditText(reason, nameof(reason), "拒绝候选必须填写理由。");
        }
        else if (!string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("确认候选不能同时填写拒绝理由。", nameof(reason));
        }

        var decidedBy = RequireAuditText(
            currentWindowsUserProvider.GetCurrentUserName(),
            nameof(currentWindowsUserProvider),
            "无法识别当前 Windows 用户，不能记录人工确认。请重新登录 Windows 后重试。");
        var decidedAt = utcNow();
        if (decidedAt == default(DateTimeOffset))
        {
            throw new InvalidOperationException("无法获取有效的确认时间，候选决议未保存。");
        }

        return repository.AppendHostSoftwareCandidateDecisionAsync(
            candidate.CandidateId,
            decision,
            decidedBy,
            ManualDecisionSource,
            normalizedReason,
            decidedAt,
            cancellationToken);
    }

    private static string RequireAuditText(string? value, string parameterName, string message)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(message, parameterName);
        }

        var normalized = value.Trim();
        foreach (var character in normalized)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("审计信息不能包含控制字符。", parameterName);
            }
        }

        return normalized;
    }
}
