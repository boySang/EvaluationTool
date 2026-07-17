using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Processes;

namespace AssessmentTool.Windows.Sessions;

internal enum NoCommandLoginOutcome
{
    Succeeded,
    AuthenticationFailed,
    HostKeyRejected,
    NetworkFailed,
    TimedOut,
    Cancelled,
    Failed
}

internal sealed class NoCommandLoginResult
{
    internal NoCommandLoginResult(NoCommandLoginOutcome outcome, string userMessage)
    {
        Outcome = outcome;
        UserMessage = string.IsNullOrWhiteSpace(userMessage)
            ? "SSH 登录测试未完成。"
            : userMessage;
    }

    internal NoCommandLoginOutcome Outcome { get; }
    internal string UserMessage { get; }
}

internal sealed class PlinkNoCommandLoginTester
{
    private static readonly TimeSpan LoginObservationTimeout = TimeSpan.FromSeconds(8);

    private readonly ICredentialLeaseFactory credentialLeaseFactory;
    private readonly IPrivateKeyFileLeaseFactory? privateKeyLeaseFactory;
    private readonly IProcessRunner processRunner;
    private readonly Encoding encoding;

    internal PlinkNoCommandLoginTester(
        ICredentialLeaseFactory credentialLeaseFactory,
        IProcessRunner processRunner,
        Encoding encoding)
        : this(credentialLeaseFactory, null, processRunner, encoding)
    {
    }

    internal PlinkNoCommandLoginTester(
        ICredentialLeaseFactory credentialLeaseFactory,
        IPrivateKeyFileLeaseFactory? privateKeyLeaseFactory,
        IProcessRunner processRunner,
        Encoding encoding)
    {
        this.credentialLeaseFactory = credentialLeaseFactory
            ?? throw new ArgumentNullException(nameof(credentialLeaseFactory));
        this.privateKeyLeaseFactory = privateKeyLeaseFactory;
        this.processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        this.encoding = Encoding.GetEncoding(
            (encoding ?? throw new ArgumentNullException(nameof(encoding))).CodePage,
            encoding.EncoderFallback,
            encoding.DecoderFallback);
    }

    internal async Task<NoCommandLoginResult> TestAsync(
        ComponentExecutionCandidate executable,
        ConnectionProfile profile,
        CancellationToken cancellationToken)
    {
        if (executable == null)
        {
            throw new ArgumentNullException(nameof(executable));
        }

        var options = RequireConfirmedProfile(profile);
        IDisposable? authenticationLease = null;
        try
        {
            string? passwordFilePath = null;
            string? privateKeyPath = null;
            if (options.AuthenticationMethod == SshAuthenticationMethod.Password)
            {
                var credentialLease = credentialLeaseFactory.Create(
                    options.CredentialReference,
                    cancellationToken);
                authenticationLease = credentialLease;
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
                privateKeyPath = privateKeyLease.Path;
            }

            var commandPlan = new PlinkArgumentsBuilder().Build(
                new PlinkArgumentsBuildRequest(profile, passwordFilePath, privateKeyPath));
            var request = ProcessRunRequest.CreateWithoutStandardInput(
                PlinkNoCommandLoginPlan.Create(commandPlan),
                LoginObservationTimeout,
                encoding);
            var processResult = await processRunner.RunAsync(executable, request, cancellationToken)
                .ConfigureAwait(false);
            return Classify(processResult);
        }
        catch (OperationCanceledException)
        {
            return new NoCommandLoginResult(NoCommandLoginOutcome.Cancelled, "已取消 SSH 登录测试。");
        }
        catch (CredentialFileLeaseException)
        {
            return new NoCommandLoginResult(NoCommandLoginOutcome.Failed, "无法安全读取登录凭据，请重新保存设备密码后重试。");
        }
        finally
        {
            authenticationLease?.Dispose();
        }
    }

    private static SshConnectionOptions RequireConfirmedProfile(ConnectionProfile profile)
    {
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        if (profile.Protocol != ConnectionProtocol.Ssh
            || profile.SshOptions == null
            || !profile.IsEligibleForAutomaticConnection)
        {
            throw new InvalidOperationException("SSH 主机指纹尚未确认，已阻止读取密码和登录。");
        }

        if (profile.SshOptions.AuthenticationMethod != SshAuthenticationMethod.Password
            && profile.SshOptions.AuthenticationMethod != SshAuthenticationMethod.PrivateKey)
        {
            throw new NotSupportedException("当前登录测试不支持该 SSH 认证方式。");
        }

        return profile.SshOptions;
    }

    private NoCommandLoginResult Classify(ProcessRunResult result)
    {
        var transcript = encoding.GetString(result.StandardError)
            + "\n"
            + encoding.GetString(result.StandardOutput);
        if (ContainsAny(transcript, "Access granted", "Authentication successful"))
        {
            return new NoCommandLoginResult(
                NoCommandLoginOutcome.Succeeded,
                "SSH 身份验证成功；测试期间未启动远程 Shell，也未发送任何命令或回车。");
        }

        if (result.Outcome == ProcessRunOutcome.Cancelled)
        {
            return new NoCommandLoginResult(NoCommandLoginOutcome.Cancelled, "已取消 SSH 登录测试。");
        }

        if (ContainsAny(transcript, "Access denied", "Authentication failed", "Wrong passphrase"))
        {
            return new NoCommandLoginResult(NoCommandLoginOutcome.AuthenticationFailed, "SSH 身份验证失败，请检查用户名以及密码或私钥。");
        }

        if (ContainsAny(transcript, "Host key did not match", "Host key verification failed"))
        {
            return new NoCommandLoginResult(NoCommandLoginOutcome.HostKeyRejected, "设备主机指纹与已确认值不一致，已阻止登录。");
        }

        if (ContainsAny(transcript, "Network error", "Connection refused", "Connection timed out", "Unable to open connection"))
        {
            return new NoCommandLoginResult(NoCommandLoginOutcome.NetworkFailed, "无法连接设备，请检查地址、端口和网络连通性。");
        }

        if (result.Outcome == ProcessRunOutcome.TimedOut)
        {
            return new NoCommandLoginResult(NoCommandLoginOutcome.TimedOut, "SSH 登录测试超时，且未观察到明确的认证成功标志。");
        }

        return new NoCommandLoginResult(NoCommandLoginOutcome.Failed, "SSH 登录测试失败，未对客户设备执行任何命令。");
    }

    private static bool ContainsAny(string value, params string[] candidates)
    {
        return candidates.Any(candidate =>
            value.IndexOf(candidate, StringComparison.OrdinalIgnoreCase) >= 0);
    }

    private sealed class PlinkNoCommandLoginPlan : ProcessArgumentPlan, IControlledPlinkArgumentPlan
    {
        private PlinkNoCommandLoginPlan(IReadOnlyList<string> argumentTokens)
            : base(argumentTokens)
        {
        }

        internal static PlinkNoCommandLoginPlan Create(PlinkArgumentsBuilder.LaunchPlan commandPlan)
        {
            if (commandPlan == null)
            {
                throw new ArgumentNullException(nameof(commandPlan));
            }

            var tokens = commandPlan.ArgumentTokens.ToList();
            var host = tokens[tokens.Count - 1];
            tokens.RemoveAt(tokens.Count - 1);
            tokens.Add("-v");
            tokens.Add("-noagent");
            tokens.Add("-noshare");
            tokens.Add("-T");
            tokens.Add("-N");
            tokens.Add("-no-trivial-auth");
            tokens.Add(host);
            return new PlinkNoCommandLoginPlan(new ReadOnlyCollection<string>(tokens));
        }
    }
}
