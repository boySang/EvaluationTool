using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Commands;

public sealed class CommandReleaseReviewerTests
{
    [Fact]
    public void Imported_metadata_factory_requires_an_explicit_reviewer_and_revalidates_the_full_pack()
    {
        var json = "{"
            + "\"id\":\"vendor-switch\","
            + "\"name\":\"厂商交换机只读命令\","
            + "\"version\":\"1.0.0\","
            + "\"officialSource\":\"https://vendor.example/docs/switch\","
            + "\"commands\":[{"
            + "\"id\":\"show-version\",\"title\":\"查看版本\","
            + "\"targetCategory\":\"NetworkDevice\",\"commandText\":\"show version\","
            + "\"verificationStatus\":\"Verified\",\"isReadOnly\":true,"
            + "\"vendor\":\"ExampleVendor\",\"productFamily\":\"ExampleSwitch\","
            + "\"minimumVersion\":\"1.0\",\"maximumVersion\":\"9.9\","
            + "\"checkItem\":\"IDENTIFY\",\"modelRange\":\"EX-*\","
            + "\"accountRequirement\":\"只读审计账户\",\"riskLevel\":\"Low\","
            + "\"timeoutSeconds\":30,\"pagingBehavior\":\"DisablePaging\","
            + "\"resultDescription\":\"设备版本信息\",\"verificationDate\":\"2026-07-18\","
            + "\"officialSource\":\"https://vendor.example/docs/show-version\",\"optional\":false"
            + "}]}";
        var draft = new CommandDraftImporter().Import(
            Encoding.UTF8.GetBytes(json),
            "vendor-switch.json",
            new DateTimeOffset(2026, 7, 18, 0, 0, 0, TimeSpan.Zero));
        var reviewedAt = new DateTimeOffset(2026, 7, 18, 1, 0, 0, TimeSpan.Zero);

        var request = CommandReleaseReviewRequestFactory.FromImportedMetadata(
            draft,
            "测评审核员",
            reviewedAt);
        var result = new CommandReleaseReviewer().Review(draft, request);

        Assert.True(result.IsPublishable);
        var candidate = Assert.IsType<CommandReleaseCandidate>(result.Candidate);
        Assert.Equal("测评审核员", candidate.ReviewedBy);
        Assert.Equal(reviewedAt, candidate.ReviewedAt);
        Assert.Equal("vendor-switch", candidate.PackId);
        Assert.Equal("1.0.0", candidate.PackVersion);
        Assert.Single(candidate.Commands);
    }

    [Fact]
    public void Review_creates_a_non_executable_canonical_candidate_after_every_command_passes_policy()
    {
        var result = Review(Draft("show version"), ValidRequest());

        Assert.True(result.IsPublishable);
        Assert.False(result.HasBlockers);
        var candidate = Assert.IsType<CommandReleaseCandidate>(result.Candidate);
        Assert.False(candidate.IsExecutable);
        Assert.Equal(Sha256(candidate.CanonicalJson), candidate.CanonicalSha256);
        Assert.DoesNotContain("\r", candidate.CanonicalJson);
        Assert.Contains(result.Findings, finding => finding.Code == "RELEASE_CANDIDATE_CREATED");

        var loaded = new CommandPackLoader().Load(
            Encoding.UTF8.GetBytes(candidate.CanonicalJson),
            candidate.CanonicalSha256);
        var command = Assert.Single(loaded.Commands);
        Assert.Equal("show-version", command.Id);
        Assert.Equal(VerificationStatus.Verified, command.VerificationStatus);
        Assert.True(command.IsReadOnly);
    }

    [Fact]
    public void Canonical_hash_is_stable_across_non_semantic_input_whitespace_and_review_audit_data()
    {
        var first = Review(Draft("show version"), ValidRequest(reviewedBy: " reviewer-a "));
        var second = Review(
            Draft("show version"),
            ValidRequest(reviewedBy: "reviewer-b", reviewedAt: new DateTimeOffset(2025, 1, 2, 0, 0, 0, TimeSpan.Zero)));

        var firstCandidate = Assert.IsType<CommandReleaseCandidate>(first.Candidate);
        var secondCandidate = Assert.IsType<CommandReleaseCandidate>(second.Candidate);
        Assert.Equal(firstCandidate.CanonicalJson, secondCandidate.CanonicalJson);
        Assert.Equal(firstCandidate.CanonicalSha256, secondCandidate.CanonicalSha256);
        Assert.Equal("reviewer-a", firstCandidate.ReviewedBy);
        Assert.Equal("reviewer-b", secondCandidate.ReviewedBy);
    }

    [Theory]
    [InlineData("echo harmless")]
    [InlineData("whoami")]
    [InlineData("curl https://example.com")]
    [InlineData("SELECT version()")]
    public void Review_rejects_arbitrary_commands_that_are_not_in_the_read_only_policy_whitelist(string commandText)
    {
        var result = Review(Draft(commandText), ValidRequest());

        Assert.False(result.IsPublishable);
        Assert.Null(result.Candidate);
        Assert.Contains(result.Findings, finding => finding.Code == "SAFETY_UNSUPPORTED_COMMAND_SHAPE");
    }

    [Fact]
    public void Review_preserves_import_blockers_and_never_creates_a_partial_candidate()
    {
        var result = Review(Draft("show version; reboot"), ValidRequest());

        Assert.True(result.HasBlockers);
        Assert.Null(result.Candidate);
        Assert.Contains(result.Findings, finding => finding.Code == "DRAFT_OBVIOUS_MUTATION");
    }

    [Theory]
    [InlineData(MissingMetadata.Source, "COMMAND_SOURCE_MISSING")]
    [InlineData(MissingMetadata.MinimumVersion, "MINIMUM_VERSION_MISSING")]
    [InlineData(MissingMetadata.MaximumVersion, "MAXIMUM_VERSION_MISSING")]
    [InlineData(MissingMetadata.Risk, "RISK_METADATA_MISSING")]
    public void Review_blocks_commands_with_missing_required_release_metadata(
        MissingMetadata missing,
        string expectedCode)
    {
        var item = ValidItem(
            minimumVersion: missing == MissingMetadata.MinimumVersion ? null : "1.0",
            maximumVersion: missing == MissingMetadata.MaximumVersion ? null : "99.0",
            riskLevel: missing == MissingMetadata.Risk ? null : CommandRiskLevel.Low,
            officialSource: missing == MissingMetadata.Source ? null : "https://vendor.example/commands/show-version");

        var result = Review(Draft("show version"), ValidRequest(commands: new[] { item }));

        Assert.Null(result.Candidate);
        Assert.Contains(result.Findings, finding => finding.Code == expectedCode && finding.CommandIndex == 0);
    }

    [Theory]
    [InlineData(CommandRiskLevel.Medium)]
    [InlineData(CommandRiskLevel.High)]
    public void Review_blocks_any_non_low_risk_command(CommandRiskLevel riskLevel)
    {
        var result = Review(
            Draft("show version"),
            ValidRequest(commands: new[] { ValidItem(riskLevel: riskLevel) }));

        Assert.False(result.IsPublishable);
        Assert.Contains(result.Findings, finding => finding.Code == "RISK_LEVEL_BLOCKED");
    }

    [Theory]
    [InlineData(null, "PACK_SOURCE_MISSING")]
    [InlineData("http://vendor.example/pack", "PACK_SOURCE_INVALID")]
    public void Review_requires_a_traceable_https_pack_source(string? source, string expectedCode)
    {
        var result = Review(Draft("show version"), ValidRequest(officialSource: source));

        Assert.Null(result.Candidate);
        Assert.Contains(result.Findings, finding => finding.Code == expectedCode);
    }

    [Fact]
    public void Review_requires_exactly_one_review_record_for_each_draft_command()
    {
        var duplicate = new[] { ValidItem(), ValidItem() };

        var result = Review(Draft("show version"), ValidRequest(commands: duplicate));

        Assert.Null(result.Candidate);
        Assert.Contains(result.Findings, finding => finding.Code == "COMMAND_REVIEW_DUPLICATE");
    }

    [Fact]
    public void One_failed_command_blocks_the_entire_multi_command_candidate()
    {
        var draft = Draft("show version", "echo bypass");
        var request = ValidRequest(commands: new[] { ValidItem(0), ValidItem(1) });

        var result = Review(draft, request);

        Assert.Null(result.Candidate);
        Assert.True(result.HasBlockers);
        Assert.Contains(result.Findings, finding => finding.CommandIndex == 1 && finding.Code.StartsWith("SAFETY_"));
    }

    [Fact]
    public void Candidate_and_review_contracts_are_immutable_and_do_not_expose_executable_domain_types()
    {
        var result = Review(Draft("show version"), ValidRequest());
        var candidate = result.Candidate!;

        var publicTypes = new[]
        {
            typeof(CommandReleaseReviewRequest),
            typeof(CommandReleaseReviewItem),
            typeof(CommandReleaseReviewFinding),
            typeof(CommandReleaseCandidateCommand),
            typeof(CommandReleaseCandidate),
            typeof(CommandReleaseReviewResult)
        };
        Assert.All(publicTypes, type =>
            Assert.All(type.GetProperties(BindingFlags.Instance | BindingFlags.Public), property =>
                Assert.False(property.CanWrite)));
        Assert.Empty(typeof(CommandReleaseCandidate).GetConstructors());
        Assert.Empty(typeof(CommandReleaseCandidateCommand).GetConstructors());
        Assert.DoesNotContain(typeof(CommandPack), ExposedMemberTypes(typeof(CommandReleaseCandidate)));
        Assert.DoesNotContain(typeof(CommandDefinition), ExposedMemberTypes(typeof(CommandReleaseCandidate)));

        var commands = Assert.IsAssignableFrom<IList<CommandReleaseCandidateCommand>>(candidate.Commands);
        Assert.Throws<NotSupportedException>(() => commands.Add(commands[0]));
        var findings = Assert.IsAssignableFrom<IList<CommandReleaseReviewFinding>>(result.Findings);
        Assert.Throws<NotSupportedException>(() => findings.Clear());
    }

    private static IEnumerable<Type> ExposedMemberTypes(Type type)
    {
        return type.GetMembers(BindingFlags.Instance | BindingFlags.Public)
            .SelectMany(member =>
            {
                if (member is PropertyInfo property)
                {
                    return new[] { property.PropertyType };
                }

                if (member is MethodInfo method)
                {
                    return new[] { method.ReturnType }
                        .Concat(method.GetParameters().Select(parameter => parameter.ParameterType));
                }

                return Array.Empty<Type>();
            });
    }

    private static CommandReleaseReviewResult Review(
        CommandDraftImportResult draft,
        CommandReleaseReviewRequest request)
    {
        return new CommandReleaseReviewer().Review(draft, request);
    }

    private static CommandDraftImportResult Draft(params string[] commandTexts)
    {
        var commands = string.Join(",", commandTexts.Select((commandText, index) =>
            "{"
            + "\"id\":\"" + (index == 0 ? "show-version" : "command-" + index) + "\","
            + "\"title\":\"查询信息\","
            + "\"targetCategory\":\"NetworkDevice\","
            + "\"commandText\":" + Newtonsoft.Json.JsonConvert.ToString(commandText) + ","
            + "\"riskLevel\":\"Low\""
            + "}"));
        var json = "{"
            + "\"id\":\"draft-pack\","
            + "\"name\":\"待审查命令\","
            + "\"version\":\"1.0.0\","
            + "\"commands\":[" + commands + "]} ";
        return new CommandDraftImporter().Import(
            Encoding.UTF8.GetBytes(json),
            "draft.json",
            new DateTimeOffset(2026, 7, 18, 0, 0, 0, TimeSpan.Zero));
    }

    private static CommandReleaseReviewRequest ValidRequest(
        string? officialSource = "https://vendor.example/command-pack",
        string? reviewedBy = "reviewer",
        DateTimeOffset? reviewedAt = null,
        IEnumerable<CommandReleaseReviewItem>? commands = null)
    {
        return new CommandReleaseReviewRequest(
            "network-readonly",
            "网络设备只读命令",
            "1.0.0",
            officialSource,
            reviewedBy,
            reviewedAt ?? new DateTimeOffset(2026, 7, 18, 1, 0, 0, TimeSpan.Zero),
            commands ?? new[] { ValidItem() });
    }

    private static CommandReleaseReviewItem ValidItem(
        int draftCommandIndex = 0,
        string? minimumVersion = "1.0",
        string? maximumVersion = "99.0",
        CommandRiskLevel? riskLevel = CommandRiskLevel.Low,
        string? officialSource = "https://vendor.example/commands/show-version")
    {
        return new CommandReleaseReviewItem(
            draftCommandIndex,
            "ExampleVendor",
            "ExampleOS",
            minimumVersion,
            maximumVersion,
            "设备版本",
            "*",
            "只读账户",
            riskLevel,
            30,
            PagingBehavior.NotApplicable,
            "记录设备软件版本。",
            new DateTime(2026, 7, 17),
            officialSource);
    }

    private static string Sha256(string value)
    {
        using (var sha256 = SHA256.Create())
        {
            return string.Concat(sha256.ComputeHash(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));
        }
    }

    public enum MissingMetadata
    {
        Source,
        MinimumVersion,
        MaximumVersion,
        Risk
    }
}
