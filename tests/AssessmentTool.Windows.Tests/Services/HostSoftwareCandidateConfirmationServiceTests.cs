using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class HostSoftwareCandidateConfirmationServiceTests
{
    private static readonly DateTimeOffset DecisionTime =
        new DateTimeOffset(2026, 7, 18, 8, 30, 0, TimeSpan.Zero);

    [Fact]
    public void Constructor_requires_repository_and_windows_user_provider()
    {
        var repository = new RecordingRepository();
        var userProvider = new StubCurrentWindowsUserProvider("CONTOSO\\assessor");

        Assert.Throws<ArgumentNullException>(
            () => new HostSoftwareCandidateConfirmationService(null!));
        Assert.Throws<ArgumentNullException>(
            () => new HostSoftwareCandidateConfirmationService(repository, null!));

        _ = new HostSoftwareCandidateConfirmationService(repository, userProvider);
    }

    [Fact]
    public async Task Confirm_records_current_windows_user_and_manual_source()
    {
        var repository = new RecordingRepository();
        var service = CreateService(repository);
        var candidate = CreateCandidate();

        var result = await service.ConfirmAsync(candidate);

        Assert.Same(repository.SavedDecision, result);
        Assert.Equal(candidate.CandidateId, result.CandidateId);
        Assert.Equal(HostSoftwareCandidateDecision.Confirmed, result.Decision);
        Assert.Equal("CONTOSO\\assessor", result.DecidedBy);
        Assert.Equal("测评人员在主机软件候选界面人工确认", result.DecisionSource);
        Assert.Null(result.Reason);
        Assert.Equal(DecisionTime, result.DecidedAt);
    }

    [Fact]
    public async Task Reject_trims_and_records_required_reason()
    {
        var repository = new RecordingRepository();
        var service = CreateService(repository);

        var result = await service.RejectAsync(CreateCandidate(), "  现场确认不是业务数据库  ");

        Assert.Equal(HostSoftwareCandidateDecision.Rejected, result.Decision);
        Assert.Equal("现场确认不是业务数据库", result.Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Reject_requires_a_non_blank_reason(string? reason)
    {
        var repository = new RecordingRepository();
        var service = CreateService(repository);

        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => service.RejectAsync(CreateCandidate(), reason!));

        Assert.Contains("理由", exception.Message);
        Assert.Null(repository.SavedDecision);
    }

    [Fact]
    public async Task Reject_reason_cannot_contain_control_characters()
    {
        var repository = new RecordingRepository();
        var service = CreateService(repository);

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.RejectAsync(CreateCandidate(), "不是目标实例\r\n请复核"));

        Assert.Null(repository.SavedDecision);
    }

    [Fact]
    public async Task Candidate_is_required()
    {
        var repository = new RecordingRepository();
        var service = CreateService(repository);

        await Assert.ThrowsAsync<ArgumentNullException>(() => service.ConfirmAsync(null!));

        Assert.Null(repository.SavedDecision);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("CONTOSO\nassessor")]
    public async Task Current_windows_user_must_be_valid_audit_text(string currentUser)
    {
        var repository = new RecordingRepository();
        var service = new HostSoftwareCandidateConfirmationService(
            repository,
            new StubCurrentWindowsUserProvider(currentUser),
            () => DecisionTime);

        await Assert.ThrowsAsync<ArgumentException>(() => service.ConfirmAsync(CreateCandidate()));

        Assert.Null(repository.SavedDecision);
    }

    [Fact]
    public async Task Superseded_cannot_be_submitted_as_an_external_manual_decision()
    {
        var repository = new RecordingRepository();
        var service = CreateService(repository);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.RecordDecisionAsync(
            CreateCandidate(),
            HostSoftwareCandidateDecision.Superseded,
            "新批次替代",
            CancellationToken.None));

        Assert.Null(repository.SavedDecision);
    }

    [Fact]
    public async Task Repository_exception_is_not_hidden_or_rewritten()
    {
        var failure = new InvalidOperationException("candidate already decided");
        var repository = new RecordingRepository { Failure = failure };
        var service = CreateService(repository);

        var actual = await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.ConfirmAsync(CreateCandidate()));

        Assert.Same(failure, actual);
    }

    private static HostSoftwareCandidateConfirmationService CreateService(
        RecordingRepository repository)
    {
        return new HostSoftwareCandidateConfirmationService(
            repository,
            new StubCurrentWindowsUserProvider("CONTOSO\\assessor"),
            () => DecisionTime);
    }

    private static HostSoftwareDiscoveryCandidateRecord CreateCandidate()
    {
        var batchId = Guid.NewGuid();
        var candidateId = Guid.NewGuid();
        var taskId = CollectionTaskId.New();
        var evidence = new HostSoftwareDiscoveryEvidenceRecord(
            Guid.NewGuid(),
            candidateId,
            0,
            taskId,
            0,
            HostSoftwareEvidenceKind.Process,
            "host-discovery-processes",
            "postgres  1240  postgres",
            new string('a', 64));
        return new HostSoftwareDiscoveryCandidateRecord(
            candidateId,
            batchId,
            0,
            HostSoftwareCategory.Database,
            "PostgreSQL",
            "16",
            HostSoftwareInstallationType.LocalService,
            "postgresql",
            "5432",
            0.92,
            new[] { evidence });
    }

    private sealed class StubCurrentWindowsUserProvider : ICurrentWindowsUserProvider
    {
        private readonly string currentUser;

        internal StubCurrentWindowsUserProvider(string currentUser)
        {
            this.currentUser = currentUser;
        }

        public string GetCurrentUserName()
        {
            return currentUser;
        }
    }

    private sealed class RecordingRepository : IHostSoftwareDiscoveryRepository
    {
        internal Exception? Failure { get; set; }
        internal HostSoftwareCandidateDecisionRecord? SavedDecision { get; private set; }

        public Task<HostSoftwareCandidateDecisionRecord> AppendHostSoftwareCandidateDecisionAsync(
            Guid candidateId,
            HostSoftwareCandidateDecision decision,
            string decidedBy,
            string decisionSource,
            string? reason,
            DateTimeOffset decidedAt,
            CancellationToken cancellationToken = default)
        {
            if (Failure != null)
            {
                return Task.FromException<HostSoftwareCandidateDecisionRecord>(Failure);
            }

            var record = new HostSoftwareCandidateDecisionRecord(
                Guid.NewGuid(),
                candidateId,
                decision,
                decidedBy,
                decisionSource,
                reason,
                decidedAt);
            SavedDecision = record;
            return Task.FromResult(record);
        }

        public Task<HostSoftwareDiscoveryBatchRecord> AppendHostSoftwareDiscoveryBatchAsync(
            ProjectId projectId,
            DeviceId deviceId,
            CollectionTaskId collectionTaskId,
            IReadOnlyList<HostSoftwareDiscoveryCandidateInput> candidates,
            string discoverySource,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<HostSoftwareDiscoveryBatchRecord?> GetLatestHostSoftwareDiscoveryBatchAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>> GetHostSoftwareDiscoveryHistoryAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<HostSoftwareCandidateDecisionRecord>> GetHostSoftwareCandidateDecisionsAsync(
            Guid batchId,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
