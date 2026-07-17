using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

internal sealed class HostSoftwareDiscoveryBatchBuilder
{
    public IReadOnlyList<HostSoftwareDiscoveryCandidateInput> Build(
        DatabaseDiscoveryResult discovery,
        IReadOnlyDictionary<string, string> rawOutputSha256ByCommand)
    {
        if (discovery == null)
        {
            throw new ArgumentNullException(nameof(discovery));
        }

        if (rawOutputSha256ByCommand == null)
        {
            throw new ArgumentNullException(nameof(rawOutputSha256ByCommand));
        }

        var inputs = discovery.DatabaseCandidates
            .Select(candidate => CreateDatabaseInput(candidate, discovery.Outputs, rawOutputSha256ByCommand))
            .Concat(discovery.MiddlewareCandidates.Select(candidate =>
                CreateMiddlewareInput(candidate, discovery.Outputs, rawOutputSha256ByCommand)))
            .ToArray();
        return new ReadOnlyCollection<HostSoftwareDiscoveryCandidateInput>(inputs);
    }

    private static HostSoftwareDiscoveryCandidateInput CreateDatabaseInput(
        DatabaseInstanceCandidate candidate,
        IReadOnlyList<CommandOutput> outputs,
        IReadOnlyDictionary<string, string> hashes)
    {
        return new HostSoftwareDiscoveryCandidateInput(
            HostSoftwareCategory.Database,
            candidate.Product,
            candidate.Version,
            candidate.InstallationType == DatabaseInstallationType.Container
                ? HostSoftwareInstallationType.Container
                : HostSoftwareInstallationType.LocalService,
            candidate.InstanceName,
            candidate.PortEvidence,
            candidate.Confidence,
            new[] { FindEvidence(candidate.Evidence, outputs, hashes) });
    }

    private static HostSoftwareDiscoveryCandidateInput CreateMiddlewareInput(
        MiddlewareInstanceCandidate candidate,
        IReadOnlyList<CommandOutput> outputs,
        IReadOnlyDictionary<string, string> hashes)
    {
        return new HostSoftwareDiscoveryCandidateInput(
            HostSoftwareCategory.Middleware,
            candidate.Product,
            candidate.Version,
            candidate.InstallationType == MiddlewareInstallationType.Container
                ? HostSoftwareInstallationType.Container
                : HostSoftwareInstallationType.LocalService,
            candidate.InstanceName,
            candidate.PortEvidence,
            candidate.Confidence,
            new[] { FindEvidence(candidate.Evidence, outputs, hashes) });
    }

    private static HostSoftwareDiscoveryEvidenceInput FindEvidence(
        string evidence,
        IReadOnlyList<CommandOutput> outputs,
        IReadOnlyDictionary<string, string> hashes)
    {
        var matches = outputs
            .Where(output => output.Outcome == RemoteExecutionOutcome.Succeeded
                && ContainsExactLine(output.StandardOutput, evidence))
            .ToArray();
        if (matches.Length != 1)
        {
            throw new InvalidOperationException(
                "主机软件候选依据无法唯一映射到已保存的只读命令输出。");
        }

        var output = matches[0];
        if (!hashes.TryGetValue(output.CommandId, out var hash))
        {
            throw new InvalidOperationException("主机软件候选缺少已保存原始输出的完整性校验值。");
        }

        return new HostSoftwareDiscoveryEvidenceInput(
            EvidenceKind(output.CommandId),
            output.CommandId,
            evidence,
            hash);
    }

    private static HostSoftwareEvidenceKind EvidenceKind(string commandId)
    {
        if (commandId.EndsWith("-processes", StringComparison.Ordinal))
        {
            return HostSoftwareEvidenceKind.Process;
        }

        if (commandId.EndsWith("-services", StringComparison.Ordinal))
        {
            return HostSoftwareEvidenceKind.Service;
        }

        if (commandId.EndsWith("-containers", StringComparison.Ordinal))
        {
            return HostSoftwareEvidenceKind.Container;
        }

        throw new InvalidOperationException("主机软件候选引用了未知的固定发现命令。");
    }

    private static bool ContainsExactLine(string transcript, string expected)
    {
        var normalizedExpected = expected.Trim();
        var start = 0;
        for (var index = 0; index <= transcript.Length; index++)
        {
            if (index < transcript.Length && transcript[index] != '\r' && transcript[index] != '\n')
            {
                continue;
            }

            if (string.Equals(
                transcript.Substring(start, index - start).Trim(),
                normalizedExpected,
                StringComparison.Ordinal))
            {
                return true;
            }

            if (index < transcript.Length
                && transcript[index] == '\r'
                && index + 1 < transcript.Length
                && transcript[index + 1] == '\n')
            {
                index++;
            }

            start = index + 1;
        }

        return false;
    }
}
