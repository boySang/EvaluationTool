using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Processes;

namespace AssessmentTool.Windows.Sessions;

public enum SshConnectionTestOutcome
{
    Succeeded,
    FingerprintFound,
    AuthenticationFailed,
    HostKeyRejected,
    NetworkFailed,
    TimedOut,
    Cancelled,
    Failed
}

public sealed class SshConnectionTestResult
{
    public SshConnectionTestResult(
        SshConnectionTestOutcome outcome,
        string userMessage,
        string? algorithm = null,
        string? fingerprint = null)
    {
        Outcome = outcome;
        UserMessage = userMessage ?? throw new ArgumentNullException(nameof(userMessage));
        Algorithm = algorithm;
        Fingerprint = fingerprint;
    }

    public SshConnectionTestOutcome Outcome { get; }
    public string UserMessage { get; }
    public string? Algorithm { get; }
    public string? Fingerprint { get; }
}

public sealed class SshConnectionTester
{
    private readonly PlinkHostKeyProbe hostKeyProbe;
    private readonly PlinkNoCommandLoginTester loginTester;

    public SshConnectionTester(ICredentialVault credentialVault)
    {
        if (credentialVault == null)
        {
            throw new ArgumentNullException(nameof(credentialVault));
        }

        var processRunner = new WindowsProcessRunner();
        var encoding = new UTF8Encoding(false, true);
        hostKeyProbe = new PlinkHostKeyProbe(processRunner, encoding);
        loginTester = new PlinkNoCommandLoginTester(
            new CredentialFileLeaseFactory(credentialVault),
            processRunner,
            encoding);
    }

    public async Task<SshConnectionTestResult> ProbeHostKeyAsync(
        ComponentExecutionCandidate executable,
        string host,
        int port,
        CancellationToken cancellationToken = default)
    {
        var result = await hostKeyProbe.ProbeAsync(
                executable,
                new SshEndpointIdentity(host, port),
                cancellationToken)
            .ConfigureAwait(false);
        return new SshConnectionTestResult(
            Map(result.Outcome),
            result.UserMessage,
            result.Algorithm,
            result.Fingerprint);
    }

    public async Task<SshConnectionTestResult> TestLoginWithoutCommandAsync(
        ComponentExecutionCandidate executable,
        ConnectionProfile profile,
        CancellationToken cancellationToken = default)
    {
        var result = await loginTester.TestAsync(executable, profile, cancellationToken)
            .ConfigureAwait(false);
        return new SshConnectionTestResult(Map(result.Outcome), result.UserMessage);
    }

    private static SshConnectionTestOutcome Map(HostKeyProbeOutcome outcome)
    {
        switch (outcome)
        {
            case HostKeyProbeOutcome.FingerprintFound:
                return SshConnectionTestOutcome.FingerprintFound;
            case HostKeyProbeOutcome.NetworkFailed:
                return SshConnectionTestOutcome.NetworkFailed;
            case HostKeyProbeOutcome.TimedOut:
                return SshConnectionTestOutcome.TimedOut;
            case HostKeyProbeOutcome.Cancelled:
                return SshConnectionTestOutcome.Cancelled;
            default:
                return SshConnectionTestOutcome.Failed;
        }
    }

    private static SshConnectionTestOutcome Map(NoCommandLoginOutcome outcome)
    {
        switch (outcome)
        {
            case NoCommandLoginOutcome.Succeeded:
                return SshConnectionTestOutcome.Succeeded;
            case NoCommandLoginOutcome.AuthenticationFailed:
                return SshConnectionTestOutcome.AuthenticationFailed;
            case NoCommandLoginOutcome.HostKeyRejected:
                return SshConnectionTestOutcome.HostKeyRejected;
            case NoCommandLoginOutcome.NetworkFailed:
                return SshConnectionTestOutcome.NetworkFailed;
            case NoCommandLoginOutcome.TimedOut:
                return SshConnectionTestOutcome.TimedOut;
            case NoCommandLoginOutcome.Cancelled:
                return SshConnectionTestOutcome.Cancelled;
            default:
                return SshConnectionTestOutcome.Failed;
        }
    }
}
