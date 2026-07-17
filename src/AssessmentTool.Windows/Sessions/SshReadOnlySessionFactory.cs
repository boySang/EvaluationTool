using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Processes;

namespace AssessmentTool.Windows.Sessions;

public sealed class SshReadOnlySessionFactory
{
    private readonly ICredentialVault credentialVault;

    public SshReadOnlySessionFactory(ICredentialVault credentialVault)
    {
        this.credentialVault = credentialVault ?? throw new ArgumentNullException(nameof(credentialVault));
    }

    public IRemoteSession Create(ConnectionProfile profile)
    {
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        if (!profile.IsEligibleForAutomaticConnection)
        {
            throw new InvalidOperationException("SSH 主机指纹尚未确认，已阻止创建采集会话。");
        }

        var inspector = new ComponentInspector();
        var status = inspector.Inspect(TrustedComponentCatalog.Plink);
        if (!status.Available)
        {
            throw new InvalidOperationException(status.UserImpact + " " + status.OfflineInstructions);
        }

        ComponentExecutionCandidate? candidate = null;
        try
        {
            candidate = inspector.RevalidateForExecution(TrustedComponentCatalog.Plink, status);
            var session = new PlinkSession(
                profile,
                candidate,
                new CredentialFileLeaseFactory(credentialVault),
                new WindowsProcessRunner(),
                new NullDiagnostics(),
                new UTF8Encoding(false, true),
                new SystemClock());
            var owned = new OwnedRemoteSession(session, candidate);
            candidate = null;
            return owned;
        }
        finally
        {
            candidate?.Dispose();
        }
    }

    private sealed class NullDiagnostics : IPlinkSessionDiagnostics
    {
        public void Record(PlinkSessionDiagnostic diagnostic)
        {
        }
    }

    private sealed class SystemClock : IPlinkSessionClock
    {
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }

    private sealed class OwnedRemoteSession : IRemoteSession, IDisposable
    {
        private readonly PlinkSession session;
        private readonly ComponentExecutionCandidate candidate;
        private bool disposed;

        internal OwnedRemoteSession(PlinkSession session, ComponentExecutionCandidate candidate)
        {
            this.session = session;
            this.candidate = candidate;
        }

        public Task<CommandOutput> ExecuteAsync(
            CommandDefinition command,
            CancellationToken cancellationToken)
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(OwnedRemoteSession));
            }

            return session.ExecuteAsync(command, cancellationToken);
        }

        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                session.Dispose();
                candidate.Dispose();
            }
        }
    }
}
