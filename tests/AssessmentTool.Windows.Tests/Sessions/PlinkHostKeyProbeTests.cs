using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Processes;
using AssessmentTool.Windows.Sessions;
using Xunit;

namespace AssessmentTool.Windows.Tests.Sessions;

public sealed class PlinkHostKeyProbeTests
{
    [Fact]
    public async Task Probe_extracts_fingerprint_without_username_credential_or_standard_input()
    {
        var transcript = "The server's ssh-ed25519 key fingerprint is:\r\nssh-ed25519 255 SHA256:fixture+/=\r\nConnection abandoned.";
        var runner = new RecordingRunner(ProcessRunResult.Completed(
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes(transcript),
            1));
        using (var candidate = CreateCandidate())
        {
            var result = await new PlinkHostKeyProbe(runner, Encoding.UTF8).ProbeAsync(
                candidate,
                new SshEndpointIdentity("router.example.test", 2222),
                CancellationToken.None);

            Assert.Equal(HostKeyProbeOutcome.FingerprintFound, result.Outcome);
            Assert.Equal("ssh-ed25519", result.Algorithm);
            Assert.Equal("ssh-ed25519 255 SHA256:fixture+/=", result.Fingerprint);
            Assert.Equal(
                new[]
                {
                    "-ssh", "-batch", "-v", "-noagent", "-noshare", "-no-antispoof",
                    "-hostkey", "ssh-ed25519 255 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "-P", "2222", "router.example.test"
                },
                runner.ArgumentTokens);
            Assert.DoesNotContain("-l", runner.ArgumentTokens);
            Assert.DoesNotContain("-pw", runner.ArgumentTokens);
            Assert.DoesNotContain("-pwfile", runner.ArgumentTokens);
            Assert.DoesNotContain("-i", runner.ArgumentTokens);
            Assert.Throws<InvalidOperationException>(() => _ = runner.Request!.Command);
            Assert.Empty(runner.Request.GetStandardInputBytes());
        }
    }

    [Fact]
    public async Task Probe_rejects_conflicting_multiple_fingerprints()
    {
        var transcript = string.Join("\r\n", new[]
        {
            "ssh-ed25519 255 SHA256:first",
            "ssh-rsa 3072 SHA256:second"
        });
        var runner = new RecordingRunner(ProcessRunResult.Completed(
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes(transcript),
            1));
        using (var candidate = CreateCandidate())
        {
            var result = await new PlinkHostKeyProbe(runner, Encoding.UTF8).ProbeAsync(
                candidate,
                new SshEndpointIdentity("router.example.test", 22),
                CancellationToken.None);

            Assert.Equal(HostKeyProbeOutcome.Failed, result.Outcome);
            Assert.Null(result.Fingerprint);
        }
    }

    [Fact]
    public async Task Probe_returns_safe_network_message_without_echoing_raw_transcript()
    {
        const string sensitiveHostText = "customer-secret-host";
        var runner = new RecordingRunner(ProcessRunResult.Completed(
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("FATAL ERROR: Network error: " + sensitiveHostText),
            1));
        using (var candidate = CreateCandidate())
        {
            var result = await new PlinkHostKeyProbe(runner, Encoding.UTF8).ProbeAsync(
                candidate,
                new SshEndpointIdentity("router.example.test", 22),
                CancellationToken.None);

            Assert.Equal(HostKeyProbeOutcome.NetworkFailed, result.Outcome);
            Assert.DoesNotContain(sensitiveHostText, result.UserMessage);
        }
    }

    private static ComponentExecutionCandidate CreateCandidate()
    {
        const string path = @"C:\Assessment Tool\components\plink.exe";
        return new ComponentExecutionCandidate(
            "plink",
            new ComponentFileIdentity(path, new string('a', 64), 128, DateTime.UtcNow, 1, 2, 1),
            path,
            new FakeComponentHandle());
    }

    private sealed class RecordingRunner : IProcessRunner
    {
        private readonly ProcessRunResult result;

        internal RecordingRunner(ProcessRunResult result)
        {
            this.result = result;
        }

        internal ProcessRunRequest? Request { get; private set; }
        internal IReadOnlyList<string> ArgumentTokens { get; private set; } = Array.Empty<string>();

        public Task<ProcessRunResult> RunAsync(
            ComponentExecutionCandidate executable,
            ProcessRunRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            ArgumentTokens = request.ArgumentTokens.ToArray();
            return Task.FromResult(result);
        }
    }

    private sealed class FakeComponentHandle : IComponentFileHandle
    {
        public Stream Stream { get; } = new MemoryStream(new byte[] { 1 }, writable: false);

        public ComponentHandleSnapshot CaptureSnapshot()
        {
            throw new NotSupportedException();
        }

        public void ValidateLease()
        {
        }

        public void Dispose()
        {
            Stream.Dispose();
        }
    }
}
