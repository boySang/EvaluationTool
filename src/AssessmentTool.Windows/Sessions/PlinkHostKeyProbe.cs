using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Processes;

namespace AssessmentTool.Windows.Sessions;

internal enum HostKeyProbeOutcome
{
    FingerprintFound,
    NetworkFailed,
    TimedOut,
    Cancelled,
    Failed
}

internal sealed class HostKeyProbeResult
{
    internal HostKeyProbeResult(
        HostKeyProbeOutcome outcome,
        string? algorithm,
        string? fingerprint,
        string userMessage)
    {
        Outcome = outcome;
        Algorithm = algorithm;
        Fingerprint = fingerprint;
        UserMessage = string.IsNullOrWhiteSpace(userMessage)
            ? "SSH 主机指纹探测未完成。"
            : userMessage;
    }

    internal HostKeyProbeOutcome Outcome { get; }
    internal string? Algorithm { get; }
    internal string? Fingerprint { get; }
    internal string UserMessage { get; }
}

internal sealed class PlinkHostKeyProbe
{
    private const string NonMatchingHostKeySentinel =
        "ssh-ed25519 255 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(12);
    private static readonly Regex FingerprintLine = new Regex(
        @"(?im)^(?<fingerprint>(?<algorithm>ssh-[A-Za-z0-9@._+-]+|ecdsa-sha2-[A-Za-z0-9@._+-]+)\s+(?:\d+\s+)?(?:SHA256:[A-Za-z0-9+/=]+|(?:[0-9a-f]{2}:){15,}[0-9a-f]{2}))\s*$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private readonly IProcessRunner processRunner;
    private readonly Encoding encoding;

    internal PlinkHostKeyProbe(IProcessRunner processRunner, Encoding encoding)
    {
        this.processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        this.encoding = Encoding.GetEncoding(
            (encoding ?? throw new ArgumentNullException(nameof(encoding))).CodePage,
            encoding.EncoderFallback,
            encoding.DecoderFallback);
    }

    internal async Task<HostKeyProbeResult> ProbeAsync(
        ComponentExecutionCandidate executable,
        SshEndpointIdentity endpoint,
        CancellationToken cancellationToken)
    {
        if (executable == null)
        {
            throw new ArgumentNullException(nameof(executable));
        }

        if (endpoint == null)
        {
            throw new ArgumentNullException(nameof(endpoint));
        }

        var request = ProcessRunRequest.CreateWithoutStandardInput(
            PlinkHostKeyProbePlan.Create(endpoint),
            ProbeTimeout,
            encoding);
        var processResult = await processRunner.RunAsync(executable, request, cancellationToken)
            .ConfigureAwait(false);
        var transcript = encoding.GetString(processResult.StandardError)
            + "\n"
            + encoding.GetString(processResult.StandardOutput);
        var matches = FingerprintLine.Matches(transcript);
        if (matches.Count == 1)
        {
            var match = matches[0];
            return new HostKeyProbeResult(
                HostKeyProbeOutcome.FingerprintFound,
                match.Groups["algorithm"].Value,
                match.Groups["fingerprint"].Value.Trim(),
                "已读取 SSH 主机指纹，请与客户提供的信息或设备控制台核对后确认。");
        }

        if (processResult.Outcome == ProcessRunOutcome.Cancelled)
        {
            return new HostKeyProbeResult(HostKeyProbeOutcome.Cancelled, null, null, "已取消 SSH 主机指纹探测。");
        }

        if (processResult.Outcome == ProcessRunOutcome.TimedOut)
        {
            return new HostKeyProbeResult(HostKeyProbeOutcome.TimedOut, null, null, "SSH 主机指纹探测超时，请检查地址、端口和防火墙。");
        }

        if (ContainsNetworkFailure(transcript))
        {
            return new HostKeyProbeResult(HostKeyProbeOutcome.NetworkFailed, null, null, "无法连接设备，请检查主机地址、SSH 端口和网络连通性。");
        }

        return new HostKeyProbeResult(HostKeyProbeOutcome.Failed, null, null, "未能安全读取 SSH 主机指纹，未使用设备密码，也未执行任何远程命令。");
    }

    private static bool ContainsNetworkFailure(string transcript)
    {
        return transcript.IndexOf("network error", StringComparison.OrdinalIgnoreCase) >= 0
            || transcript.IndexOf("connection refused", StringComparison.OrdinalIgnoreCase) >= 0
            || transcript.IndexOf("connection timed out", StringComparison.OrdinalIgnoreCase) >= 0
            || transcript.IndexOf("unable to open connection", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private sealed class PlinkHostKeyProbePlan : ProcessArgumentPlan, IControlledPlinkArgumentPlan
    {
        private PlinkHostKeyProbePlan(IReadOnlyList<string> argumentTokens)
            : base(argumentTokens)
        {
        }

        internal static PlinkHostKeyProbePlan Create(SshEndpointIdentity endpoint)
        {
            var tokens = new[]
            {
                "-ssh",
                "-batch",
                "-v",
                "-noagent",
                "-noshare",
                "-no-antispoof",
                "-hostkey",
                NonMatchingHostKeySentinel,
                "-P",
                endpoint.Port.ToString(CultureInfo.InvariantCulture),
                endpoint.Host
            };
            return new PlinkHostKeyProbePlan(new ReadOnlyCollection<string>(tokens));
        }
    }
}
