using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Processes;

namespace AssessmentTool.Windows.Sessions;

internal interface IPlinkSessionDiagnostics
{
    void Record(PlinkSessionDiagnostic diagnostic);
}

internal interface IPlinkSessionClock
{
    DateTimeOffset UtcNow { get; }
}

internal interface IPrivateKeyFileLeaseFactory
{
    IPrivateKeyFileLease Create(
        PrivateKeyReference privateKeyReference,
        CancellationToken cancellationToken);
}

internal interface IPrivateKeyFileLease : IDisposable
{
    string Path { get; }

    string RedactedIdentifier { get; }
}

internal sealed class PlinkSessionDiagnostic
{
    internal PlinkSessionDiagnostic(
        string code,
        string credentialIdentifier,
        ProcessFailureStage failureStage)
    {
        Code = string.IsNullOrWhiteSpace(code) ? "unknown" : code;
        CredentialIdentifier = SanitizeCredentialIdentifier(credentialIdentifier);
        FailureStage = failureStage;
    }

    internal string Code { get; }
    internal string CredentialIdentifier { get; }
    internal ProcessFailureStage FailureStage { get; }

    public override string ToString()
    {
        return Code + "|" + FailureStage + "|" + CredentialIdentifier;
    }

    private static string SanitizeCredentialIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64)
        {
            return "credential-redacted";
        }

        foreach (var character in value)
        {
            var allowed =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '-' ||
                character == '_';
            if (!allowed)
            {
                return "credential-redacted";
            }
        }

        return value;
    }
}

internal sealed class PlinkSession : IRemoteSession, IDisposable
{
    private readonly ConnectionProfile profile;
    private readonly ComponentExecutionCandidate executable;
    private readonly ICredentialLeaseFactory credentialLeaseFactory;
    private readonly IPrivateKeyFileLeaseFactory? privateKeyLeaseFactory;
    private readonly IProcessRunner processRunner;
    private readonly IPlinkSessionDiagnostics diagnostics;
    private readonly Encoding encoding;
    private readonly IPlinkSessionClock clock;
    private readonly CommandSafetyPolicy safetyPolicy = new CommandSafetyPolicy();
    private readonly SemaphoreSlim executionLock = new SemaphoreSlim(1, 1);
    private int disposed;

    internal PlinkSession(
        ConnectionProfile profile,
        ComponentExecutionCandidate executable,
        ICredentialLeaseFactory credentialLeaseFactory,
        IProcessRunner processRunner,
        IPlinkSessionDiagnostics diagnostics,
        Encoding encoding,
        IPlinkSessionClock clock)
        : this(
            profile,
            executable,
            credentialLeaseFactory,
            null,
            processRunner,
            diagnostics,
            encoding,
            clock)
    {
    }

    internal PlinkSession(
        ConnectionProfile profile,
        ComponentExecutionCandidate executable,
        ICredentialLeaseFactory credentialLeaseFactory,
        IPrivateKeyFileLeaseFactory? privateKeyLeaseFactory,
        IProcessRunner processRunner,
        IPlinkSessionDiagnostics diagnostics,
        Encoding encoding,
        IPlinkSessionClock clock)
    {
        this.profile = profile ?? throw new ArgumentNullException(nameof(profile));
        this.executable = executable ?? throw new ArgumentNullException(nameof(executable));
        this.credentialLeaseFactory = credentialLeaseFactory
            ?? throw new ArgumentNullException(nameof(credentialLeaseFactory));
        this.privateKeyLeaseFactory = privateKeyLeaseFactory;
        this.processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        this.diagnostics = diagnostics ?? throw new ArgumentNullException(nameof(diagnostics));
        this.encoding = SnapshotEncoding(encoding ?? throw new ArgumentNullException(nameof(encoding)));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    public async Task<CommandOutput> ExecuteAsync(
        CommandDefinition command,
        CancellationToken cancellationToken)
    {
        if (command == null)
        {
            throw new ArgumentNullException(nameof(command));
        }

        var startedAt = clock.UtcNow;
        try
        {
            await executionLock.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return Stopped(command.Id, startedAt, RemoteFailureCategory.Cancelled);
        }

        try
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(PlinkSession));
            }

            return await ExecuteLockedAsync(command, startedAt, cancellationToken);
        }
        finally
        {
            executionLock.Release();
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref disposed, 1);
    }

    private async Task<CommandOutput> ExecuteLockedAsync(
        CommandDefinition command,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken)
    {
        IDisposable? authenticationLease = null;
        ProcessRunResult? processResult = null;
        string credentialIdentifier = "credential-unavailable";
        RemoteFailureCategory? preparationFailure = null;
        try
        {
            var safetyDecision = safetyPolicy.Validate(command);
            if (!safetyDecision.Allowed)
            {
                diagnostics.Record(new PlinkSessionDiagnostic(
                    safetyDecision.Code,
                    credentialIdentifier,
                    ProcessFailureStage.SafetyValidation));
                return Failed(
                    command.Id,
                    string.Empty,
                    string.Empty,
                    null,
                    startedAt,
                    RemoteFailureCategory.UnsafeCommand);
            }

            var options = RequireSshOptions();
            string? passwordFilePath = null;
            string? privateKeyPath = null;
            if (options.AuthenticationMethod == SshAuthenticationMethod.Password)
            {
                var credentialLease = credentialLeaseFactory.Create(
                    options.CredentialReference,
                    cancellationToken);
                authenticationLease = credentialLease;
                credentialIdentifier = credentialLease.RedactedIdentifier;
                passwordFilePath = credentialLease.Path;
            }
            else
            {
                if (!options.PrivateKeyReference.HasValue || privateKeyLeaseFactory == null)
                {
                    throw new InvalidOperationException("当前未安装受信任的私钥文件提供组件。");
                }

                var privateKeyLease = privateKeyLeaseFactory.Create(
                    options.PrivateKeyReference.Value,
                    cancellationToken);
                authenticationLease = privateKeyLease;
                credentialIdentifier = privateKeyLease.RedactedIdentifier;
                privateKeyPath = privateKeyLease.Path;
            }

            var argumentPlan = new PlinkArgumentsBuilder().Build(
                new PlinkArgumentsBuildRequest(profile, passwordFilePath, privateKeyPath));
            processResult = await processRunner.RunAsync(
                executable,
                new ProcessRunRequest(argumentPlan, command, encoding, encoding),
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            preparationFailure = RemoteFailureCategory.Cancelled;
        }
        catch (CredentialFileLeaseException)
        {
            preparationFailure = RemoteFailureCategory.ProcessFailed;
        }
        catch (InvalidOperationException)
        {
            preparationFailure = IsHostKeyBlocked()
                ? RemoteFailureCategory.HostKeyRejected
                : RemoteFailureCategory.ProcessFailed;
        }
        catch (ArgumentException)
        {
            preparationFailure = RemoteFailureCategory.ProcessFailed;
        }

        try
        {
            authenticationLease?.Dispose();
        }
        catch (Exception)
        {
            diagnostics.Record(new PlinkSessionDiagnostic(
                "credential-cleanup-failed",
                credentialIdentifier,
                ProcessFailureStage.ProcessTermination));
            return Failed(
                command.Id,
                string.Empty,
                string.Empty,
                null,
                startedAt,
                RemoteFailureCategory.ProcessFailed);
        }

        if (preparationFailure.HasValue)
        {
            var stopped = preparationFailure.Value == RemoteFailureCategory.Cancelled;
            diagnostics.Record(new PlinkSessionDiagnostic(
                stopped ? "cancelled" : "session-preparation-failed",
                credentialIdentifier,
                ProcessFailureStage.ProcessCreation));
            return stopped
                ? Stopped(command.Id, startedAt, RemoteFailureCategory.Cancelled)
                : Failed(
                    command.Id,
                    string.Empty,
                    string.Empty,
                    null,
                    startedAt,
                    preparationFailure.Value);
        }

        if (processResult == null)
        {
            diagnostics.Record(new PlinkSessionDiagnostic(
                "process-result-missing",
                credentialIdentifier,
                ProcessFailureStage.ProcessWait));
            return Failed(
                command.Id,
                string.Empty,
                string.Empty,
                null,
                startedAt,
                RemoteFailureCategory.ProcessFailed);
        }

        return MapProcessResult(command.Id, processResult, credentialIdentifier, startedAt);
    }

    private CommandOutput MapProcessResult(
        string commandId,
        ProcessRunResult result,
        string credentialIdentifier,
        DateTimeOffset startedAt)
    {
        var standardOutput = encoding.GetString(result.StandardOutput);
        var standardError = encoding.GetString(result.StandardError);
        switch (result.Outcome)
        {
            case ProcessRunOutcome.Succeeded:
                return new CommandOutput(
                    commandId,
                    standardOutput,
                    standardError,
                    result.ExitCode,
                    RemoteExecutionOutcome.Succeeded,
                    null,
                    startedAt,
                    clock.UtcNow);
            case ProcessRunOutcome.Cancelled:
                return Stopped(
                    commandId,
                    startedAt,
                    RemoteFailureCategory.Cancelled,
                    standardOutput,
                    standardError);
            case ProcessRunOutcome.TimedOut:
                return Stopped(
                    commandId,
                    startedAt,
                    RemoteFailureCategory.TimedOut,
                    standardOutput,
                    standardError);
            default:
                var failureCategory = ClassifyFailure(result, standardOutput, standardError);
                diagnostics.Record(new PlinkSessionDiagnostic(
                    result.FailureCode ?? "plink-process-failed",
                    credentialIdentifier,
                    result.FailureStage));
                return Failed(
                    commandId,
                    standardOutput,
                    standardError,
                    result.ExitCode,
                    startedAt,
                    failureCategory);
        }
    }

    private SshConnectionOptions RequireSshOptions()
    {
        if (profile.Protocol != ConnectionProtocol.Ssh || profile.SshOptions == null)
        {
            throw new InvalidOperationException("SSH 连接资料不完整。");
        }

        if (!profile.IsEligibleForAutomaticConnection)
        {
            throw new InvalidOperationException("SSH 主机指纹尚未确认或连接资料不完整。");
        }

        return profile.SshOptions;
    }

    private bool IsHostKeyBlocked()
    {
        var trust = profile.SshOptions?.HostKeyTrust;
        return trust == null ||
            (trust.State != HostKeyTrustState.Pinned && trust.State != HostKeyTrustState.Verified);
    }

    private static RemoteFailureCategory ClassifyFailure(
        ProcessRunResult result,
        string standardOutput,
        string standardError)
    {
        if (result.FailureStage == ProcessFailureStage.SafetyValidation)
        {
            return RemoteFailureCategory.UnsafeCommand;
        }

        var transcript = standardError + "\n" + standardOutput;
        if (ContainsAny(transcript, "access denied", "authentication failed", "wrong passphrase"))
        {
            return RemoteFailureCategory.AuthenticationFailed;
        }

        if (ContainsAny(
            transcript,
            "host key did not match",
            "host key is not cached",
            "host key verification failed"))
        {
            return RemoteFailureCategory.HostKeyRejected;
        }

        if (ContainsAny(
            transcript,
            "network error",
            "unable to open connection",
            "connection refused",
            "connection timed out"))
        {
            return RemoteFailureCategory.NetworkFailed;
        }

        return RemoteFailureCategory.ProcessFailed;
    }

    private static bool ContainsAny(string value, params string[] candidates)
    {
        foreach (var candidate in candidates)
        {
            if (value.IndexOf(candidate, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private CommandOutput Stopped(
        string commandId,
        DateTimeOffset startedAt,
        RemoteFailureCategory failureCategory,
        string standardOutput = "",
        string standardError = "")
    {
        return new CommandOutput(
            commandId,
            standardOutput,
            standardError,
            null,
            RemoteExecutionOutcome.Stopped,
            failureCategory,
            startedAt,
            clock.UtcNow);
    }

    private CommandOutput Failed(
        string commandId,
        string standardOutput,
        string standardError,
        int? exitCode,
        DateTimeOffset startedAt,
        RemoteFailureCategory failureCategory)
    {
        return new CommandOutput(
            commandId,
            standardOutput,
            standardError,
            exitCode,
            RemoteExecutionOutcome.Failed,
            failureCategory,
            startedAt,
            clock.UtcNow);
    }

    private static Encoding SnapshotEncoding(Encoding value)
    {
        return Encoding.GetEncoding(value.CodePage, value.EncoderFallback, value.DecoderFallback);
    }
}
