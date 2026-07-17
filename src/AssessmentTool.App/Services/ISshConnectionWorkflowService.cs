using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Sessions;

namespace AssessmentTool.App.Services;

public sealed class SshConnectionWorkflowResult
{
    public SshConnectionWorkflowResult(
        SshHostKeyTrustRecord trustRecord,
        SshConnectionTestResult connectionResult)
    {
        TrustRecord = trustRecord;
        ConnectionResult = connectionResult;
    }

    public SshHostKeyTrustRecord TrustRecord { get; }
    public SshConnectionTestResult ConnectionResult { get; }
}

public interface ISshConnectionWorkflowService
{
    Task<SshHostKeyTrustRecord> GetTrustAsync(
        DeviceRecord device,
        CancellationToken cancellationToken = default);
    Task<SshConnectionWorkflowResult> ProbeAsync(
        DeviceRecord device,
        CancellationToken cancellationToken = default);
    Task<SshConnectionWorkflowResult> ConfirmAndTestAsync(
        DeviceRecord device,
        CancellationToken cancellationToken = default);
}
