using System;
using System.Collections.Generic;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Domain;

public sealed class DomainContractTests
{
    [Fact]
    public void ConnectionProfile_defaults_to_automatic_detection()
    {
        var profile = new ConnectionProfile("交换机A", "192.0.2.10", 22, ConnectionProtocol.Ssh);

        Assert.Equal(TargetCategory.Automatic, profile.TargetCategory);
        Assert.Equal("交换机A", profile.DisplayName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ConnectionProfile_rejects_blank_display_name(string displayName)
    {
        Assert.Throws<ArgumentException>(() =>
            new ConnectionProfile(displayName, "192.0.2.10", 22, ConnectionProtocol.Ssh));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ConnectionProfile_rejects_blank_host(string host)
    {
        Assert.Throws<ArgumentException>(() =>
            new ConnectionProfile("交换机A", host, 22, ConnectionProtocol.Ssh));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void ConnectionProfile_rejects_ports_outside_tcp_range(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ConnectionProfile("交换机A", "192.0.2.10", port, ConnectionProtocol.Ssh));
    }

    [Fact]
    public void CommandDefinition_retains_required_assessment_metadata()
    {
        var command = CreateCommand(VerificationStatus.Pending, false);

        Assert.Equal("1.1.1", command.CheckItem);
        Assert.Equal("ASR 1000", command.ModelRange);
        Assert.Equal("只读审计账户", command.AccountRequirement);
        Assert.Equal(CommandRiskLevel.Low, command.RiskLevel);
        Assert.Equal(TimeSpan.FromSeconds(30), command.Timeout);
        Assert.Equal(PagingBehavior.DisablePaging, command.PagingBehavior);
        Assert.Equal("确认系统版本", command.ResultDescription);
        Assert.Equal(new DateTime(2025, 2, 3), command.VerificationDate);
        Assert.Equal("https://example.com/commands/show-version", command.OfficialSource);
    }

    [Theory]
    [InlineData(VerificationStatus.Pending, true, false)]
    [InlineData(VerificationStatus.Rejected, true, false)]
    [InlineData(VerificationStatus.Verified, false, false)]
    [InlineData(VerificationStatus.Verified, true, true)]
    public void CommandDefinition_derives_automatic_execution_eligibility(
        VerificationStatus verificationStatus,
        bool isReadOnly,
        bool expectedEligibility)
    {
        var command = CreateCommand(verificationStatus, isReadOnly);

        Assert.Equal(expectedEligibility, command.IsEligibleForAutomaticExecution);
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    [InlineData(-0.01)]
    [InlineData(1.01)]
    public void DetectionCandidate_rejects_non_finite_or_out_of_range_confidence(double confidence)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            CreateCandidate(confidence));
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(0.9)]
    [InlineData(1.0)]
    public void DetectionCandidate_accepts_confidence_within_closed_unit_interval(double confidence)
    {
        var candidate = CreateCandidate(confidence);

        Assert.Equal(confidence, candidate.Confidence);
    }

    [Fact]
    public void DetectionCandidate_keeps_product_family_and_model_as_separate_immutable_values()
    {
        var candidate = new DetectionCandidate(
            TargetCategory.NetworkDevice,
            "厂商",
            "系列",
            "X1000",
            "1.0",
            "版本横幅",
            1.0);

        Assert.Equal("系列", candidate.ProductFamily);
        Assert.Equal("X1000", candidate.Model);
        Assert.Null(typeof(DetectionCandidate).GetProperty("Product"));
    }

    [Fact]
    public void DetectionCandidate_allows_a_null_model_only_when_model_is_unknown()
    {
        var candidate = new DetectionCandidate(
            TargetCategory.NetworkDevice,
            "厂商",
            "系列",
            null,
            "1.0",
            "版本横幅",
            1.0);

        Assert.Null(candidate.Model);
    }

    [Fact]
    public void DetectionResult_does_not_require_confirmation_for_one_high_confidence_candidate()
    {
        var result = new DetectionResult(new[] { CreateCandidate(0.9) });

        Assert.False(result.RequiresUserConfirmation);
    }

    [Fact]
    public void DetectionResult_requires_confirmation_for_one_high_confidence_automatic_candidate()
    {
        var candidate = new DetectionCandidate(
            TargetCategory.Automatic,
            "厂商",
            "系列",
            "X1000",
            "1.0",
            "版本横幅",
            1.0);

        var result = new DetectionResult(new[] { candidate });

        Assert.True(result.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData(0.89)]
    [InlineData(0.0)]
    public void DetectionResult_requires_confirmation_for_one_candidate_below_threshold(double confidence)
    {
        var result = new DetectionResult(new[] { CreateCandidate(confidence) });

        Assert.True(result.RequiresUserConfirmation);
    }

    [Fact]
    public void DetectionResult_requires_confirmation_when_candidate_count_is_not_one()
    {
        var result = new DetectionResult(new[] { CreateCandidate(0.95), CreateCandidate(0.99) });

        Assert.True(result.RequiresUserConfirmation);
    }

    [Fact]
    public void DetectionResult_copies_candidates_into_an_immutable_list()
    {
        var candidates = new List<DetectionCandidate> { CreateCandidate(0.9) };
        var result = new DetectionResult(candidates);
        candidates.Clear();

        Assert.Single(result.Candidates);
        Assert.Equal("版本横幅", result.Candidates[0].Evidence);
    }

    [Fact]
    public void DetectionResult_confirm_preserves_original_confidence_and_marks_user_confirmation()
    {
        var candidate = CreateCandidate(0.42);
        var result = new DetectionResult(new[] { candidate });

        var confirmed = result.Confirm(candidate);

        Assert.True(confirmed.WasUserConfirmed);
        Assert.False(confirmed.RequiresUserConfirmation);
        Assert.Equal(0.42, Assert.Single(confirmed.Candidates).Confidence);
    }

    [Fact]
    public void DetectionResult_confirm_uses_the_fresh_current_candidate_after_revalidation()
    {
        var freshCandidate = CreateCandidate(0.42);
        var persistedEquivalent = new DetectionCandidate(
            freshCandidate.Category,
            freshCandidate.Vendor,
            freshCandidate.ProductFamily,
            freshCandidate.Model,
            freshCandidate.Version,
            freshCandidate.Evidence,
            freshCandidate.Confidence);
        var result = new DetectionResult(new[] { freshCandidate });

        var confirmed = result.Confirm(persistedEquivalent);

        Assert.Same(freshCandidate, Assert.Single(confirmed.Candidates));
    }

    [Fact]
    public void DetectionResult_confirm_rejects_automatic_candidate()
    {
        var candidate = new DetectionCandidate(
            TargetCategory.Automatic,
            "厂商",
            "系列",
            "X1000",
            "1.0",
            "版本横幅",
            1.0);
        var result = new DetectionResult(new[] { candidate });

        Assert.Throws<ArgumentException>(() => result.Confirm(candidate));
    }

    [Fact]
    public void DetectionResult_confirm_rejects_candidate_outside_current_candidates()
    {
        var result = new DetectionResult(new[] { CreateCandidate(0.8) });
        var outsideCandidate = new DetectionCandidate(
            TargetCategory.Server,
            "其他厂商",
            "其他系列",
            "S2000",
            "2.0",
            "其他识别依据",
            0.8);

        Assert.Throws<ArgumentException>(() => result.Confirm(outsideCandidate));
    }

    [Theory]
    [InlineData("Category")]
    [InlineData("Vendor")]
    [InlineData("ProductFamily")]
    [InlineData("Model")]
    [InlineData("Version")]
    [InlineData("Evidence")]
    [InlineData("Confidence")]
    public void DetectionResult_confirm_rejects_candidate_with_tampered_field(string field)
    {
        var candidate = CreateCandidate(0.8);
        var result = new DetectionResult(new[] { candidate });
        var tamperedCandidate = new DetectionCandidate(
            field == "Category" ? TargetCategory.Server : candidate.Category,
            field == "Vendor" ? "其他厂商" : candidate.Vendor,
            field == "ProductFamily" ? "其他系列" : candidate.ProductFamily,
            field == "Model" ? "S2000" : candidate.Model,
            field == "Version" ? "2.0" : candidate.Version,
            field == "Evidence" ? "其他识别依据" : candidate.Evidence,
            field == "Confidence" ? 0.81 : candidate.Confidence);

        Assert.Throws<ArgumentException>(() => result.Confirm(tamperedCandidate));
    }

    [Fact]
    public void ExecutionRecord_accepts_complete_successful_record_and_defensively_copies_evidence()
    {
        var startedAt = DateTimeOffset.UtcNow;
        var evidencePaths = new List<string> { "page-1.png" };
        var evidenceHashes = new Dictionary<string, string>
        {
            ["page-1.png"] = ValidSha256Uppercase
        };
        var record = new ExecutionRecord(
            "project-1",
            "device-1",
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            "cmd-1",
            "show version",
            startedAt,
            startedAt.AddSeconds(1),
            ExecutionStatus.Succeeded,
            0,
            "raw.txt",
            ValidSha256,
            evidencePaths,
            evidenceHashes,
            null);
        evidencePaths.Clear();
        evidenceHashes.Clear();

        Assert.Equal("project-1", record.ProjectId);
        Assert.Equal("device-1", record.DeviceId);
        Assert.Equal(ConnectionProtocol.Ssh, record.ConnectionProtocol);
        Assert.Equal("pack-1.2.3", record.CommandPackVersion);
        Assert.Equal(ExecutionStatus.Succeeded, record.Status);
        Assert.Equal(0, record.ExitCode);
        Assert.Equal(ValidSha256, record.RawOutputSha256);
        Assert.Equal(ValidSha256Uppercase, record.EvidenceImageSha256s["page-1.png"]);
        Assert.Single(record.EvidenceImagePaths);
    }

    [Fact]
    public void ExecutionRecord_rejects_succeeded_record_without_raw_output_hash()
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Succeeded,
            "raw.txt",
            null,
            new[] { "page-1.png" },
            new Dictionary<string, string> { ["page-1.png"] = ValidSha256 }));
    }

    [Theory]
    [InlineData("not-a-sha256")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")]
    public void ExecutionRecord_rejects_malformed_raw_output_hash(string rawOutputSha256)
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            rawOutputSha256,
            Array.Empty<string>(),
            new Dictionary<string, string>()));
    }

    [Fact]
    public void ExecutionRecord_rejects_succeeded_record_with_missing_image_hash()
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Succeeded,
            "raw.txt",
            ValidSha256,
            new[] { "page-1.png" },
            new Dictionary<string, string>()));
    }

    [Fact]
    public void ExecutionRecord_rejects_succeeded_record_with_extra_image_hash()
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Succeeded,
            "raw.txt",
            ValidSha256,
            new[] { "page-1.png" },
            new Dictionary<string, string>
            {
                ["page-1.png"] = ValidSha256,
                ["page-2.png"] = ValidSha256
            }));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ExecutionRecord_rejects_blank_evidence_image_paths(string evidenceImagePath)
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { evidenceImagePath },
            new Dictionary<string, string>()));
    }

    [Fact]
    public void ExecutionRecord_rejects_duplicate_evidence_image_paths()
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { "page-1.png", "page-1.png" },
            new Dictionary<string, string>()));
    }

    [Fact]
    public void ExecutionRecord_rejects_non_success_record_with_unmatched_or_malformed_image_hash()
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { "page-1.png" },
            new Dictionary<string, string> { ["page-2.png"] = ValidSha256 }));

        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { "page-1.png" },
            new Dictionary<string, string> { ["page-1.png"] = "not-a-sha256" }));
    }

    [Fact]
    public void ExecutionRecord_rejects_undefined_protocol_and_status_values()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ExecutionRecord(
            "project-1",
            "device-1",
            (ConnectionProtocol)999,
            "pack-1.2.3",
            "cmd-1",
            "show version",
            DateTimeOffset.UtcNow,
            null,
            ExecutionStatus.Failed,
            null,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>(),
            "failed"));

        Assert.Throws<ArgumentOutOfRangeException>(() => new ExecutionRecord(
            "project-1",
            "device-1",
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            "cmd-1",
            "show version",
            DateTimeOffset.UtcNow,
            null,
            (ExecutionStatus)999,
            null,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>(),
            "failed"));
    }

    [Fact]
    public void ExecutionRecord_requires_hash_for_every_raw_and_image_path_regardless_of_status()
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            "raw.txt",
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>()));

        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { "page-1.png" },
            new Dictionary<string, string>()));

        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            ValidSha256,
            Array.Empty<string>(),
            new Dictionary<string, string>()));
    }

    [Fact]
    public void ExecutionRecord_uses_ordinal_ignore_case_for_evidence_hash_keys()
    {
        var record = CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { "Screens\\Page-1.PNG" },
            new Dictionary<string, string> { ["screens\\page-1.png"] = ValidSha256 });

        Assert.Equal(ValidSha256, record.EvidenceImageSha256s["SCREENS\\PAGE-1.PNG"]);
    }

    [Fact]
    public void ExecutionRecord_allows_failed_record_without_evidence()
    {
        var record = CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>());

        Assert.Empty(record.EvidenceImagePaths);
        Assert.Empty(record.EvidenceImageSha256s);
    }

    [Fact]
    public void ExecutionRecord_normalizes_raw_image_and_hash_key_paths_before_matching()
    {
        var record = new ExecutionRecord(
            "project-1",
            "device-1",
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            "cmd-1",
            "show version",
            DateTimeOffset.UtcNow,
            null,
            ExecutionStatus.Failed,
            null,
            "raw/output.txt",
            ValidSha256,
            new[] { "screens/page-1.png" },
            new Dictionary<string, string> { [@"screens\page-1.png"] = ValidSha256Uppercase },
            "failed");

        Assert.Equal(@"raw\output.txt", record.RawOutputPath);
        Assert.Equal(@"screens\page-1.png", Assert.Single(record.EvidenceImagePaths));
        Assert.Equal(ValidSha256Uppercase, record.EvidenceImageSha256s[@"screens\page-1.png"]);
        Assert.Equal(@"screens\page-1.png", Assert.Single(record.EvidenceImageSha256s.Keys));
    }

    [Fact]
    public void ExecutionRecord_rejects_separator_equivalent_duplicate_image_paths()
    {
        Assert.Throws<ArgumentException>(() => new ExecutionRecord(
            "project-1",
            "device-1",
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            "cmd-1",
            "show version",
            DateTimeOffset.UtcNow,
            null,
            ExecutionStatus.Failed,
            null,
            null,
            null,
            new[] { "screens/page.png", @"screens\page.png" },
            new Dictionary<string, string> { [@"screens\page.png"] = ValidSha256 },
            "failed"));
    }

    [Theory]
    [InlineData(@"..\outside.txt")]
    [InlineData(@"screens\..\outside.txt")]
    [InlineData(@"C:\outside.txt")]
    public void ExecutionRecord_rejects_unsafe_raw_image_and_hash_key_paths(string unsafePath)
    {
        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            unsafePath,
            ValidSha256,
            Array.Empty<string>(),
            new Dictionary<string, string>()));

        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { unsafePath },
            new Dictionary<string, string> { [unsafePath] = ValidSha256 }));

        Assert.Throws<ArgumentException>(() => CreateExecutionRecord(
            ExecutionStatus.Failed,
            null,
            null,
            new[] { "page.png" },
            new Dictionary<string, string> { [unsafePath] = ValidSha256 }));
    }

    private const string ValidSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ValidSha256Uppercase = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    private static CommandDefinition CreateCommand(VerificationStatus verificationStatus, bool isReadOnly)
    {
        return new CommandDefinition(
            "cmd-1",
            "查询版本",
            TargetCategory.NetworkDevice,
            "show version",
            verificationStatus,
            isReadOnly,
            "Cisco",
            "ASR",
            "1.0",
            "2.0",
            "1.1.1",
            "ASR 1000",
            "只读审计账户",
            CommandRiskLevel.Low,
            TimeSpan.FromSeconds(30),
            PagingBehavior.DisablePaging,
            "确认系统版本",
            new DateTime(2025, 2, 3),
            "https://example.com/commands/show-version");
    }

    private static DetectionCandidate CreateCandidate(double confidence)
    {
        return new DetectionCandidate(
            TargetCategory.NetworkDevice,
            "厂商",
            "系列",
            "X1000",
            "1.0",
            "版本横幅",
            confidence);
    }

    private static ExecutionRecord CreateExecutionRecord(
        ExecutionStatus status,
        string? rawOutputPath,
        string? rawOutputSha256,
        IEnumerable<string> evidenceImagePaths,
        IDictionary<string, string> evidenceImageSha256s)
    {
        return new ExecutionRecord(
            "project-1",
            "device-1",
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            "cmd-1",
            "show version",
            DateTimeOffset.UtcNow,
            null,
            status,
            null,
            rawOutputPath,
            rawOutputSha256,
            evidenceImagePaths,
            evidenceImageSha256s,
            null);
    }
}
