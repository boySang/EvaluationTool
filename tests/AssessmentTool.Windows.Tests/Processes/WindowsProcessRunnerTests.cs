using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Processes;
using AssessmentTool.Windows.Sessions;
using Microsoft.Win32.SafeHandles;
using Xunit;

namespace AssessmentTool.Windows.Tests.Processes;

public sealed class WindowsProcessRunnerTests
{
    private const string ExecutablePath = @"C:\Assessment Tool\components\collector.exe";
    private const string PlinkExecutablePath = @"C:\Assessment Tool\components\plink.exe";
    private const string SafeCommandText = "display version";

    [Fact]
    public void Runner_contract_exposes_only_candidate_request_and_cancellation()
    {
        Assert.False(typeof(IProcessRunner).IsPublic);
        var run = Assert.Single(typeof(IProcessRunner).GetMethods());
        Assert.Equal("RunAsync", run.Name);
        Assert.Equal(
            new[] { typeof(ComponentExecutionCandidate), typeof(ProcessRunRequest), typeof(CancellationToken) },
            run.GetParameters().Select(parameter => parameter.ParameterType));

        var requestProperties = typeof(ProcessRunRequest).GetProperties(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        Assert.Equal(4, requestProperties.Length);
        Assert.All(requestProperties, property => Assert.False(property.CanWrite));
        Assert.DoesNotContain(
            requestProperties,
            property => property.PropertyType == typeof(string)
                || property.PropertyType.FullName == "System.Diagnostics.ProcessStartInfo");
    }

    [Fact]
    public void Request_snapshots_argument_tokens_and_requires_encodings()
    {
        var tokens = new List<string> { "-ssh", "server.example" };
        var mutableInput = (Encoding)Encoding.UTF8.Clone();
        mutableInput.EncoderFallback = new EncoderReplacementFallback("[before]");
        var request = new ProcessRunRequest(
            ProcessArgumentPlan.FromTokens(tokens),
            SafeCommand(),
            mutableInput,
            Encoding.Unicode);

        tokens[0] = "changed";
        mutableInput.EncoderFallback = new EncoderReplacementFallback("[after]");

        Assert.Equal(new[] { "-ssh", "server.example" }, request.ArgumentTokens);
        Assert.Equal(
            "[before]",
            Assert.IsType<EncoderReplacementFallback>(request.InputEncoding.EncoderFallback).DefaultString);
        var returnedEncoding = request.InputEncoding;
        returnedEncoding.EncoderFallback = new EncoderReplacementFallback("[returned]");
        Assert.Equal(
            "[before]",
            Assert.IsType<EncoderReplacementFallback>(request.InputEncoding.EncoderFallback).DefaultString);
        Assert.Equal(Encoding.Unicode, request.OutputEncoding);
        Assert.Throws<ArgumentNullException>(() => new ProcessRunRequest(
            ProcessArgumentPlan.FromTokens(tokens),
            SafeCommand(),
            null!,
            Encoding.UTF8));
        Assert.Throws<ArgumentException>(() => ProcessArgumentPlan.FromTokens(new[] { "valid", null! }));
    }

    [Theory]
    [InlineData("plink", @"C:\Assessment Tool\components\renamed-helper.exe")]
    [InlineData("custom-tool", PlinkExecutablePath)]
    public async Task Generic_argument_plan_cannot_launch_plink_candidate(
        string componentId,
        string executablePath)
    {
        var api = new FakeWindowsProcessApi();
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api, executablePath, componentId))
        {
            var request = Request(
                SafeCommand(),
                new[] { "-ssh", "-pw", "secret", "-proxycmd", "evil", "router.example.test" });

            var result = await runner.RunAsync(candidate, request, CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.SafetyValidation, result.FailureStage);
            Assert.Equal("plink-plan-required", result.FailureCode);
            Assert.Empty(api.Calls);
        }
    }

    [Fact]
    public async Task Builder_created_plink_plan_launches_without_raw_password_or_proxy_arguments()
    {
        var api = new FakeWindowsProcessApi();
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api, PlinkExecutablePath, "plink"))
        {
            var request = new ProcessRunRequest(
                CreatePlinkPlan(),
                SafeCommand(),
                Encoding.UTF8,
                Encoding.UTF8);

            var result = await runner.RunAsync(candidate, request, CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Succeeded, result.Outcome);
            Assert.Equal(PlinkExecutablePath, api.ApplicationName);
            Assert.DoesNotContain(" -pw ", api.CommandLine, StringComparison.Ordinal);
            Assert.DoesNotContain("-proxycmd", api.CommandLine, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(" -pwfile ", api.CommandLine, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Unsafe_command_is_rejected_before_any_native_api_call()
    {
        var api = new FakeWindowsProcessApi();
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate())
        {
            var request = Request(CreateCommand("show version | configure terminal", VerificationStatus.Verified, true));

            var result = await runner.RunAsync(candidate, request, CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.SafetyValidation, result.FailureStage);
            Assert.Equal("unsafe-command", result.FailureCode);
            Assert.Empty(api.Calls);
        }
    }

    [Fact]
    public async Task Launch_uses_serializer_nonempty_application_name_flags_handle_list_and_locked_order()
    {
        var api = new FakeWindowsProcessApi();
        var runner = new WindowsProcessRunner(api);
        var tokens = new[] { "-ssh", "设备 01", @"C:\keys\key\" };
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(candidate, Request(SafeCommand(), tokens), CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Succeeded, result.Outcome);
            Assert.Equal(ExecutablePath, api.ApplicationName);
            Assert.Equal(
                "\"" + ExecutablePath + "\" " + WindowsArgumentSerializer.Serialize(tokens),
                api.CommandLine);
            Assert.Equal(
                WindowsProcessCreationFlags.CreateSuspended
                    | WindowsProcessCreationFlags.CreateNoWindow
                    | WindowsProcessCreationFlags.ExtendedStartupInfoPresent,
                api.CreationFlags);
            Assert.Equal(api.Pipes.Select(pipe => pipe.ChildHandle.DangerousGetHandle()), api.InheritedHandles);
            Assert.Equal(
                new[]
                {
                    "CreatePipe:StandardInput",
                    "CreatePipe:StandardOutput",
                    "CreatePipe:StandardError",
                    "CreateKillOnCloseJob",
                    "CreateStartupAttributeList",
                    "CreateProcess",
                    "AssignProcessToJob",
                    "ResumePrimaryThread",
                    "WaitForExitAsync",
                    "GetExitCode"
                },
                api.Calls);
            Assert.True(api.AllLaunchCallsObservedValidatedLease);
            Assert.True(api.JobConfiguredToKillOnClose);
        }
    }

    [Theory]
    [MemberData(nameof(TrustedCommandLineCases))]
    public async Task Trusted_argv0_and_serialized_argv1_have_exact_command_line_and_parse_round_trip(
        string executablePath,
        string[] argumentTokens,
        string expectedCommandLine)
    {
        var api = new FakeWindowsProcessApi();
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api, executablePath))
        {
            var result = await runner.RunAsync(
                candidate,
                Request(SafeCommand(), argumentTokens),
                CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Succeeded, result.Outcome);
            Assert.Equal(executablePath, api.ApplicationName);
            Assert.Equal(expectedCommandLine, api.CommandLine);
            Assert.Equal(
                new[] { executablePath }.Concat(argumentTokens),
                ParseWindowsCommandLine(api.CommandLine!));
        }
    }

    [Fact]
    public void Trusted_argv0_quote_function_accepts_only_application_name()
    {
        var quote = typeof(WindowsProcessRunner).GetMethod(
            "QuoteTrustedApplicationName",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(quote);
        var parameter = Assert.Single(quote!.GetParameters());
        Assert.Equal(typeof(string), parameter.ParameterType);
        Assert.Equal("applicationName", parameter.Name);
        Assert.Equal(
            "\"C:\\测评 工具\\组件\\plink.exe\"",
            quote.Invoke(null, new object[] { @"C:\测评 工具\组件\plink.exe" }));
    }

    [Theory]
    [InlineData("C:\\Assessment Tool\\bad\"name.exe")]
    [InlineData("C:\\Assessment Tool\\bad\0name.exe")]
    [InlineData("C:\\Assessment Tool\\bad\rname.exe")]
    [InlineData("C:\\Assessment Tool\\bad\nname.exe")]
    [InlineData("relative\\plink.exe")]
    public async Task Invalid_trusted_application_name_is_rejected_before_native_calls(string executablePath)
    {
        var api = new FakeWindowsProcessApi();
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api, executablePath))
        {
            var result = await runner.RunAsync(candidate, Request(SafeCommand()), CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.ProcessCreation, result.FailureStage);
            Assert.Equal("invalid-application-name", result.FailureCode);
            Assert.Empty(api.Calls);
        }
    }

    [Fact]
    public async Task Assign_failure_terminates_suspended_process_without_resuming_it()
    {
        var api = new FakeWindowsProcessApi { AssignErrorCode = 5 };
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(candidate, Request(SafeCommand()), CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.JobAssignment, result.FailureStage);
            Assert.Equal(5, result.NativeErrorCode);
            Assert.Contains("TerminateProcess", api.Calls);
            Assert.DoesNotContain("ResumePrimaryThread", api.Calls);
            Assert.False(api.ProcessWasResumed);
        }
    }

    [Fact]
    public async Task Assign_and_suspended_process_termination_failure_returns_termination_failure()
    {
        var api = new FakeWindowsProcessApi
        {
            AssignErrorCode = 5,
            TerminateProcessErrorCode = 31
        };
        var runner = new WindowsProcessRunner(api, TimeSpan.FromMilliseconds(20));
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(candidate, Request(SafeCommand()), CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.ProcessTermination, result.FailureStage);
            Assert.Equal(31, result.NativeErrorCode);
            Assert.DoesNotContain("ResumePrimaryThread", api.Calls);
        }
    }

    [Fact]
    public async Task Resume_failure_terminates_assigned_suspended_process_without_running_it()
    {
        var api = new FakeWindowsProcessApi { ResumeErrorCode = 31 };
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(candidate, Request(SafeCommand()), CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.ThreadResume, result.FailureStage);
            Assert.Equal(31, result.NativeErrorCode);
            Assert.Contains("TerminateJob", api.Calls);
            Assert.False(api.ProcessWasResumed);
        }
    }

    [Fact]
    public async Task Resume_and_job_termination_failure_returns_termination_failure()
    {
        var api = new FakeWindowsProcessApi
        {
            ResumeErrorCode = 31,
            TerminateJobErrorCode = 5
        };
        var runner = new WindowsProcessRunner(api, TimeSpan.FromMilliseconds(20));
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(candidate, Request(SafeCommand()), CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.ProcessTermination, result.FailureStage);
            Assert.Equal(5, result.NativeErrorCode);
            Assert.False(api.ProcessWasResumed);
        }
    }

    [Fact]
    public async Task Reads_stdout_and_stderr_concurrently_and_returns_exact_bytes()
    {
        var reads = new ConcurrentReadGate();
        var stdout = new byte[] { 0x00, 0xff, 0x31 };
        var stderr = new byte[] { 0xe4, 0xb8, 0xad };
        var api = new FakeWindowsProcessApi(
            new CoordinatedReadStream(stdout, reads),
            new CoordinatedReadStream(stderr, reads));
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(candidate, Request(SafeCommand()), CancellationToken.None);

            Assert.Equal(stdout, result.StandardOutput);
            Assert.Equal(stderr, result.StandardError);
            Assert.True(reads.BothReadersEntered);
        }
    }

    [Fact]
    public async Task Writes_only_command_text_and_crlf_to_stdin_then_closes_it()
    {
        var input = new TrackingWriteStream();
        var api = new FakeWindowsProcessApi(input: input);
        var runner = new WindowsProcessRunner(api);
        var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(
                candidate,
                new ProcessRunRequest(
                    ProcessArgumentPlan.FromTokens(new[] { "-batch" }),
                    SafeCommand(),
                    encoding,
                    Encoding.UTF8),
                CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Succeeded, result.Outcome);
            Assert.Equal(encoding.GetBytes(SafeCommandText + "\r\n"), input.WrittenBytes);
            Assert.True(input.WasClosed);
            Assert.DoesNotContain(SafeCommandText, string.Join("|", api.Calls));
        }
    }

    [Fact]
    public async Task Controlled_plink_connection_check_closes_stdin_without_sending_any_bytes()
    {
        var input = new TrackingWriteStream();
        var api = new FakeWindowsProcessApi(input: input);
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api, PlinkExecutablePath, "plink"))
        {
            var request = ProcessRunRequest.CreateWithoutStandardInput(
                CreatePlinkPlan(),
                TimeSpan.FromSeconds(5),
                Encoding.UTF8);

            var result = await runner.RunAsync(candidate, request, CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Succeeded, result.Outcome);
            Assert.Empty(input.WrittenBytes);
            Assert.True(input.WasClosed);
        }
    }

    [Fact]
    public async Task Generic_plan_cannot_bypass_command_safety_with_no_input_mode()
    {
        var api = new FakeWindowsProcessApi();
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api))
        {
            var request = ProcessRunRequest.CreateWithoutStandardInput(
                ProcessArgumentPlan.FromTokens(new[] { "--probe" }),
                TimeSpan.FromSeconds(5),
                Encoding.UTF8);

            var result = await runner.RunAsync(candidate, request, CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal("connection-check-plan-required", result.FailureCode);
            Assert.Empty(api.Calls);
        }
    }

    [Fact]
    public async Task Runner_sends_the_same_trimmed_command_text_that_the_safety_policy_validates()
    {
        var input = new TrackingWriteStream();
        var api = new FakeWindowsProcessApi(input: input);
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(
                candidate,
                Request(CreateCommand("  display version  ", VerificationStatus.Verified, true)),
                CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.Succeeded, result.Outcome);
            Assert.Equal(Encoding.UTF8.GetBytes("display version\r\n"), input.WrittenBytes);
        }
    }

    [Fact]
    public async Task Cancellation_terminates_job_and_drains_remaining_output()
    {
        using (var cancellation = new CancellationTokenSource())
        {
            var api = FakeWindowsProcessApi.WaitUntilTerminated(
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5 });
            var runner = new WindowsProcessRunner(api);
            using (var candidate = CreateCandidate(api))
            {
                var run = runner.RunAsync(candidate, Request(SafeCommand()), cancellation.Token);
                await api.WaitStarted;

                cancellation.Cancel();
                var result = await run;

                Assert.Equal(ProcessRunOutcome.Cancelled, result.Outcome);
                Assert.Equal(new byte[] { 1, 2, 3 }, result.StandardOutput);
                Assert.Equal(new byte[] { 4, 5 }, result.StandardError);
                Assert.Contains("TerminateJob", api.Calls);
                Assert.True(api.Input.WasClosed);
            }
        }
    }

    [Fact]
    public async Task Cancellation_returns_bounded_termination_failure_when_job_termination_fails()
    {
        using (var cancellation = new CancellationTokenSource())
        {
            var api = FakeWindowsProcessApi.WaitUntilTerminated(Array.Empty<byte>(), Array.Empty<byte>());
            api.TerminateJobErrorCode = 5;
            var runner = new WindowsProcessRunner(api, TimeSpan.FromMilliseconds(20));
            using (var candidate = CreateCandidate(api))
            {
                var run = runner.RunAsync(candidate, Request(SafeCommand()), cancellation.Token);
                await api.WaitStarted;
                cancellation.Cancel();

                var completed = await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(1)));
                Assert.Same(run, completed);
                var result = await run;
                Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
                Assert.Equal(ProcessFailureStage.ProcessTermination, result.FailureStage);
                Assert.Equal(5, result.NativeErrorCode);
            }
        }
    }

    [Fact]
    public async Task Stdin_failure_after_process_exit_is_returned_as_structured_failure()
    {
        var input = new DelayedFailingWriteStream();
        var api = new FakeWindowsProcessApi(input: input);
        var runner = new WindowsProcessRunner(api, TimeSpan.FromMilliseconds(20));
        using (var candidate = CreateCandidate(api))
        {
            var run = runner.RunAsync(candidate, Request(SafeCommand()), CancellationToken.None);
            await input.WriteStarted;
            input.FailWrite();

            var result = await run;
            Assert.Equal(ProcessRunOutcome.Failed, result.Outcome);
            Assert.Equal(ProcessFailureStage.StandardInput, result.FailureStage);
            Assert.Equal("stdin-write-failed", result.FailureCode);
        }
    }

    [Fact]
    public async Task Timeout_terminates_job_drains_output_and_returns_only_safe_failure_metadata()
    {
        const string secretToken = "secret-argument";
        var command = CreateCommand(SafeCommandText, VerificationStatus.Verified, true, TimeSpan.FromMilliseconds(50));
        var api = FakeWindowsProcessApi.WaitUntilTerminated(new byte[] { 9, 8 }, new byte[] { 7 });
        var runner = new WindowsProcessRunner(api);
        using (var candidate = CreateCandidate(api))
        {
            var result = await runner.RunAsync(candidate, Request(command, new[] { secretToken }), CancellationToken.None);

            Assert.Equal(ProcessRunOutcome.TimedOut, result.Outcome);
            Assert.Equal(new byte[] { 9, 8 }, result.StandardOutput);
            Assert.Equal(new byte[] { 7 }, result.StandardError);
            Assert.Equal(ProcessFailureStage.ProcessWait, result.FailureStage);
            var metadata = result.FailureCode + "|" + result.FailureStage + "|" + result.NativeErrorCode;
            Assert.DoesNotContain(ExecutablePath, metadata);
            Assert.DoesNotContain(secretToken, metadata);
            Assert.DoesNotContain(SafeCommandText, metadata);
        }
    }

    private static ProcessRunRequest Request(CommandDefinition command, IReadOnlyList<string>? tokens = null)
    {
        return new ProcessRunRequest(
            ProcessArgumentPlan.FromTokens(tokens ?? new[] { "-batch" }),
            command,
            Encoding.UTF8,
            Encoding.UTF8);
    }

    private static CommandDefinition SafeCommand()
    {
        return CreateCommand(SafeCommandText, VerificationStatus.Verified, true);
    }

    private static CommandDefinition CreateCommand(
        string commandText,
        VerificationStatus verificationStatus,
        bool isReadOnly,
        TimeSpan? timeout = null)
    {
        var constructor = Assert.Single(
            typeof(CommandDefinition).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic));
        return (CommandDefinition)constructor.Invoke(new object?[]
        {
            "cmd-1",
            "查询版本",
            TargetCategory.NetworkDevice,
            commandText,
            verificationStatus,
            isReadOnly,
            "Vendor",
            "Series",
            "1.0",
            "2.0",
            "1.1.1",
            "all",
            "readonly",
            CommandRiskLevel.Low,
            timeout ?? TimeSpan.FromSeconds(5),
            PagingBehavior.NotApplicable,
            "版本信息",
            new DateTime(2026, 7, 16),
            "https://vendor.example/docs",
            false,
            null
        });
    }

    public static IEnumerable<object[]> TrustedCommandLineCases()
    {
        yield return new object[]
        {
            ExecutablePath,
            Array.Empty<string>(),
            "\"C:\\Assessment Tool\\components\\collector.exe\""
        };
        yield return new object[]
        {
            @"C:\测评 工具\组件\collector.exe",
            new[] { "设备01" },
            "\"C:\\测评 工具\\组件\\collector.exe\" 设备01"
        };
        yield return new object[]
        {
            ExecutablePath,
            new[] { "-ssh", "设备 01" },
            "\"C:\\Assessment Tool\\components\\collector.exe\" -ssh \"设备 01\""
        };
    }

    private static PlinkArgumentsBuilder.LaunchPlan CreatePlinkPlan()
    {
        var endpoint = new SshEndpointIdentity("router.example.test", 22);
        var observedAt = new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint));
        var awaiting = coordinator.RecordObservation(
            probing,
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            observedAt);
        var trust = coordinator.Confirm(
            awaiting,
            observedAt.AddMinutes(1),
            "设备控制台核对");
        var options = new SshConnectionOptions(
            endpoint,
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            trust);
        var profile = new ConnectionProfile(
            "核心交换机",
            endpoint.Host,
            endpoint.Port,
            ConnectionProtocol.Ssh,
            options);

        return new PlinkArgumentsBuilder().Build(new PlinkArgumentsBuildRequest(
            profile,
            @"C:\Assessment Tool\凭据\password.txt",
            null));
    }

    private static IReadOnlyList<string> ParseWindowsCommandLine(string commandLine)
    {
        var arguments = new List<string>();
        var index = 0;
        while (index < commandLine.Length)
        {
            while (index < commandLine.Length && char.IsWhiteSpace(commandLine[index]))
            {
                index++;
            }

            if (index == commandLine.Length)
            {
                break;
            }

            var argument = new StringBuilder();
            var insideQuotes = false;
            while (index < commandLine.Length && (insideQuotes || !char.IsWhiteSpace(commandLine[index])))
            {
                var backslashes = 0;
                while (index < commandLine.Length && commandLine[index] == '\\')
                {
                    backslashes++;
                    index++;
                }

                if (index < commandLine.Length && commandLine[index] == '"')
                {
                    argument.Append('\\', backslashes / 2);
                    if (backslashes % 2 == 0)
                    {
                        insideQuotes = !insideQuotes;
                    }
                    else
                    {
                        argument.Append('"');
                    }

                    index++;
                    continue;
                }

                argument.Append('\\', backslashes);
                if (index < commandLine.Length && (insideQuotes || !char.IsWhiteSpace(commandLine[index])))
                {
                    argument.Append(commandLine[index]);
                    index++;
                }
            }

            Assert.False(insideQuotes);
            arguments.Add(argument.ToString());
        }

        return arguments;
    }

    private static ComponentExecutionCandidate CreateCandidate(
        FakeWindowsProcessApi? api = null,
        string executablePath = ExecutablePath,
        string componentId = "test.generic")
    {
        var identity = new ComponentFileIdentity(
            executablePath,
            new string('a', 64),
            128,
            new DateTime(2026, 7, 16, 0, 0, 0, DateTimeKind.Utc),
            1,
            2,
            1);
        return new ComponentExecutionCandidate(
            componentId,
            identity,
            executablePath,
            new FakeComponentFileHandle(api));
    }

    private sealed class FakeComponentFileHandle : IComponentFileHandle
    {
        private readonly FakeWindowsProcessApi? api;
        private bool disposed;
        private int validations;

        public FakeComponentFileHandle(FakeWindowsProcessApi? api)
        {
            this.api = api;
            Stream = new MemoryStream(new byte[] { 1 }, writable: false);
        }

        public Stream Stream { get; }

        public ComponentHandleSnapshot CaptureSnapshot()
        {
            throw new NotSupportedException();
        }

        public void ValidateLease()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(FakeComponentFileHandle));
            }

            validations++;
            if (api != null)
            {
                api.LeaseIsValidatedForLaunch = validations == 1;
            }
        }

        public void Dispose()
        {
            disposed = true;
            Stream.Dispose();
        }
    }

    private sealed class FakeWindowsProcessApi : IWindowsProcessApi
    {
        private readonly Stream stdout;
        private readonly Stream stderr;
        private readonly TaskCompletionSource<int> exit =
            new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> waitStarted =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly bool waitsForTermination;
        private int nextHandle = 100;

        public FakeWindowsProcessApi(
            Stream? stdout = null,
            Stream? stderr = null,
            TrackingWriteStream? input = null,
            bool waitsForTermination = false)
        {
            this.stdout = stdout ?? new MemoryStream(Array.Empty<byte>(), writable: false);
            this.stderr = stderr ?? new MemoryStream(Array.Empty<byte>(), writable: false);
            Input = input ?? new TrackingWriteStream();
            this.waitsForTermination = waitsForTermination;
            if (!waitsForTermination)
            {
                exit.TrySetResult(0);
            }
        }

        public List<string> Calls { get; } = new List<string>();
        public List<WindowsProcessPipe> Pipes { get; } = new List<WindowsProcessPipe>();
        public TrackingWriteStream Input { get; }
        public Task WaitStarted => waitStarted.Task;
        public string? ApplicationName { get; private set; }
        public string? CommandLine { get; private set; }
        public WindowsProcessCreationFlags CreationFlags { get; private set; }
        public IReadOnlyList<IntPtr> InheritedHandles { get; private set; } = Array.Empty<IntPtr>();
        public int? AssignErrorCode { get; set; }
        public int? ResumeErrorCode { get; set; }
        public int? TerminateProcessErrorCode { get; set; }
        public int? TerminateJobErrorCode { get; set; }
        public bool ProcessWasResumed { get; private set; }
        public bool JobConfiguredToKillOnClose { get; private set; }
        public bool LeaseIsValidatedForLaunch { private get; set; }
        public bool AllLaunchCallsObservedValidatedLease { get; private set; } = true;

        public static FakeWindowsProcessApi WaitUntilTerminated(byte[] stdout, byte[] stderr)
        {
            return new FakeWindowsProcessApi(
                new MemoryStream(stdout, writable: false),
                new MemoryStream(stderr, writable: false),
                waitsForTermination: true);
        }

        public WindowsProcessPipe CreatePipe(ProcessPipeKind kind)
        {
            ObserveLaunchCall("CreatePipe:" + kind);
            Stream parent = kind == ProcessPipeKind.StandardInput
                ? Input
                : kind == ProcessPipeKind.StandardOutput ? stdout : stderr;
            var pipe = new WindowsProcessPipe(
                kind,
                new SafeFileHandle(new IntPtr(nextHandle++), ownsHandle: false),
                parent);
            Pipes.Add(pipe);
            return pipe;
        }

        public IWindowsJob CreateKillOnCloseJob()
        {
            ObserveLaunchCall("CreateKillOnCloseJob");
            JobConfiguredToKillOnClose = true;
            return new FakeJob();
        }

        public IWindowsStartupAttributeList CreateStartupAttributeList(IReadOnlyList<IntPtr> inheritedHandles)
        {
            ObserveLaunchCall("CreateStartupAttributeList");
            InheritedHandles = inheritedHandles.ToArray();
            return new FakeStartupAttributes();
        }

        public IWindowsProcess CreateProcess(
            string applicationName,
            string commandLine,
            WindowsProcessCreationFlags creationFlags,
            WindowsProcessPipe standardInput,
            WindowsProcessPipe standardOutput,
            WindowsProcessPipe standardError,
            IWindowsStartupAttributeList startupAttributes)
        {
            ObserveLaunchCall("CreateProcess");
            ApplicationName = applicationName;
            CommandLine = commandLine;
            CreationFlags = creationFlags;
            return new FakeProcess();
        }

        public void AssignProcessToJob(IWindowsJob job, IWindowsProcess process)
        {
            ObserveLaunchCall("AssignProcessToJob");
            if (AssignErrorCode.HasValue)
            {
                throw new WindowsProcessNativeException(ProcessFailureStage.JobAssignment, AssignErrorCode.Value);
            }
        }

        public void ResumePrimaryThread(IWindowsProcess process)
        {
            ObserveLaunchCall("ResumePrimaryThread");
            if (ResumeErrorCode.HasValue)
            {
                throw new WindowsProcessNativeException(ProcessFailureStage.ThreadResume, ResumeErrorCode.Value);
            }

            ProcessWasResumed = true;
        }

        public Task WaitForExitAsync(IWindowsProcess process)
        {
            Calls.Add("WaitForExitAsync");
            waitStarted.TrySetResult(true);
            return exit.Task;
        }

        public int GetExitCode(IWindowsProcess process)
        {
            Calls.Add("GetExitCode");
            return exit.Task.GetAwaiter().GetResult();
        }

        public void TerminateProcess(IWindowsProcess process, uint exitCode)
        {
            Calls.Add("TerminateProcess");
            if (TerminateProcessErrorCode.HasValue)
            {
                throw new WindowsProcessNativeException(
                    ProcessFailureStage.ProcessTermination,
                    TerminateProcessErrorCode.Value);
            }

            this.exit.TrySetResult(unchecked((int)exitCode));
        }

        public void TerminateJob(IWindowsJob job, uint exitCode)
        {
            Calls.Add("TerminateJob");
            if (TerminateJobErrorCode.HasValue)
            {
                throw new WindowsProcessNativeException(
                    ProcessFailureStage.ProcessTermination,
                    TerminateJobErrorCode.Value);
            }

            this.exit.TrySetResult(unchecked((int)exitCode));
        }

        private void ObserveLaunchCall(string call)
        {
            Calls.Add(call);
            AllLaunchCallsObservedValidatedLease &= LeaseIsValidatedForLaunch;
        }

        private sealed class FakeProcess : IWindowsProcess
        {
            public void Dispose()
            {
            }
        }

        private sealed class FakeJob : IWindowsJob
        {
            public void Dispose()
            {
            }
        }

        private sealed class FakeStartupAttributes : IWindowsStartupAttributeList
        {
            public void Dispose()
            {
            }
        }
    }

    private class TrackingWriteStream : MemoryStream
    {
        public bool WasClosed { get; private set; }
        public byte[] WrittenBytes => ToArray();

        protected override void Dispose(bool disposing)
        {
            WasClosed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class DelayedFailingWriteStream : TrackingWriteStream
    {
        private readonly TaskCompletionSource<bool> writeStarted =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> release =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        internal Task WriteStarted => writeStarted.Task;

        internal void FailWrite()
        {
            release.TrySetException(new IOException("synthetic stdin failure"));
        }

        public override async Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            writeStarted.TrySetResult(true);
            await release.Task;
        }
    }

    private sealed class ConcurrentReadGate
    {
        private readonly TaskCompletionSource<bool> release =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private int readers;

        public bool BothReadersEntered => Volatile.Read(ref readers) == 2;

        public Task EnterAsync()
        {
            if (Interlocked.Increment(ref readers) == 2)
            {
                release.TrySetResult(true);
            }

            return release.Task;
        }
    }

    private sealed class CoordinatedReadStream : MemoryStream
    {
        private readonly ConcurrentReadGate gate;
        private bool entered;

        public CoordinatedReadStream(byte[] bytes, ConcurrentReadGate gate)
            : base(bytes, writable: false)
        {
            this.gate = gate;
        }

        public override async Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            if (!entered)
            {
                entered = true;
                await gate.EnterAsync();
            }

            return await base.ReadAsync(buffer, offset, count, cancellationToken);
        }
    }
}
