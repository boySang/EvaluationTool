using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Detection;

public sealed class DetectionEngineTests
{
    [Fact]
    public void Unique_high_confidence_match_is_accepted_automatically()
    {
        var result = Engine().Detect("VendorA Network OS 7.2 Model X100", Rules());

        Assert.False(result.RequiresUserConfirmation);
        Assert.Equal("VendorA", Assert.Single(result.Candidates).Vendor);
    }

    [Fact]
    public void Conflicting_matches_require_user_confirmation()
    {
        var rules = new[]
        {
            Rule(@"^(?<vendor>VendorA) compatible VendorB shell$"),
            Rule(@"^VendorA compatible (?<vendor>VendorB) shell$")
        };

        var result = Engine().Detect("VendorA compatible VendorB shell", rules);

        Assert.True(result.RequiresUserConfirmation);
        Assert.True(result.Candidates.Count >= 2);
    }

    [Fact]
    public void Unknown_output_does_not_guess()
    {
        var result = Engine().Detect("unknown appliance", Rules());

        Assert.True(result.RequiresUserConfirmation);
        Assert.Empty(result.Candidates);
    }

    [Fact]
    public void Missing_version_capture_does_not_infer_a_version_from_the_evidence()
    {
        var rule = Rule(@"^(?<vendor>VendorA) Network OS 7\.2 Model (?<model>X100)$");

        var candidate = Assert.Single(Engine().Detect("VendorA Network OS 7.2 Model X100", new[] { rule }).Candidates);

        Assert.Null(candidate.Version);
    }

    [Fact]
    public void Product_family_and_model_are_captured_independently()
    {
        var rule = Rule(@"^(?<vendor>VendorA) (?<productFamily>Network OS) Model (?<model>X100)$");

        var candidate = Assert.Single(Engine().Detect("VendorA Network OS Model X100", new[] { rule }).Candidates);

        Assert.Equal("Network OS", candidate.ProductFamily);
        Assert.Equal("X100", candidate.Model);
    }

    [Fact]
    public void Verified_factory_rejects_an_invalid_regular_expression()
    {
        Assert.Throws<ArgumentException>(() => Rule(@"^(?<vendor>VendorA)(?<broken>$"));
    }

    [Fact]
    public void Verified_factory_rejects_a_null_pattern()
    {
        Assert.Throws<ArgumentNullException>(() =>
            IdentificationRule.CreateVerified(TargetCategory.NetworkDevice, null!, 0.95, VerifiedSource));
    }

    [Fact]
    public void Identification_rules_have_no_public_construction_or_factory_bypass()
    {
        var publicFactories = typeof(IdentificationRule)
            .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(method => method.ReturnType == typeof(IdentificationRule));

        Assert.Empty(typeof(IdentificationRule).GetConstructors());
        Assert.Empty(publicFactories);
    }

    [Fact]
    public void Internal_factory_creates_a_verified_rule_with_immutable_source_metadata()
    {
        var rule = Rule(DefaultPattern);

        Assert.Equal(VerificationStatus.Verified, rule.VerificationStatus);
        Assert.Equal(VerifiedSource, rule.VerifiedSource);
    }

    [Fact]
    public void Internal_verified_factory_rejects_a_blank_source()
    {
        Assert.Throws<ArgumentException>(() =>
            IdentificationRule.CreateVerified(TargetCategory.NetworkDevice, DefaultPattern, 0.95, " "));
    }

    [Fact]
    public void Timed_out_rule_fails_closed_even_when_another_rule_matches()
    {
        var matchingRule = Rule(DefaultPattern);
        var timedOutRule = Rule(@"^(?<vendor>(a+)+)$");
        var transcript = "VendorA Network OS 7.2 Model X100\n" + new string('a', 10_000) + "!";

        var result = Engine().Detect(transcript, new[] { matchingRule, timedOutRule });

        Assert.True(result.RequiresUserConfirmation);
        Assert.Empty(result.Candidates);
    }

    [Fact]
    public void Duplicate_rules_produce_one_candidate_without_a_false_conflict()
    {
        var rule = Rule(DefaultPattern);

        var result = Engine().Detect("VendorA Network OS 7.2 Model X100", new[] { rule, rule });

        Assert.False(result.RequiresUserConfirmation);
        Assert.Single(result.Candidates);
    }

    [Fact]
    public void Repeated_matches_with_identical_product_semantics_are_deduplicated()
    {
        var rule = Rule(DefaultPattern);
        var transcript = "VendorA Network OS 7.2 Model X100\nVendorA Network OS 7.2 Model X100";

        var result = Engine().Detect(transcript, new[] { rule });

        Assert.False(result.RequiresUserConfirmation);
        Assert.Single(result.Candidates);
        Assert.Equal("VendorA Network OS 7.2 Model X100", result.Candidates[0].Evidence);
    }

    [Fact]
    public void Candidates_with_equal_confidence_have_a_deterministic_product_order()
    {
        var rules = new[]
        {
            Rule(@"^(?<vendor>VendorZ) shell$"),
            Rule(@"^(?<vendor>VendorA) shell$")
        };

        var result = Engine().Detect("VendorA shell\nVendorZ shell", rules);

        Assert.Equal(new[] { "VendorA", "VendorZ" }, result.Candidates.Select(candidate => candidate.Vendor));
    }

    [Fact]
    public void Matching_is_case_insensitive_but_requires_the_anchored_rule_boundary()
    {
        var rule = Rule(@"^(?<vendor>VendorA) Network OS (?<version>7\.2) Model (?<model>X100)$");

        var matched = Engine().Detect("vendora network os 7.2 model x100", new[] { rule });
        var notMatched = Engine().Detect("prefix VendorA Network OS 7.2 Model X100 suffix", new[] { rule });

        Assert.Single(matched.Candidates);
        Assert.Empty(notMatched.Candidates);
    }

    [Fact]
    public void Top_level_alternation_cannot_bypass_the_complete_match_boundary()
    {
        var rule = Rule(@"^(?<vendor>VendorA)|VendorB$");

        var result = Engine().Detect("VendorA arbitrary text", new[] { rule });

        Assert.Empty(result.Candidates);
        Assert.True(result.RequiresUserConfirmation);
    }

    [Fact]
    public void Candidate_preserves_the_exact_matched_evidence()
    {
        var rule = Rule(@"^(?<vendor>VendorA) Network OS (?<version>7\.2) Model (?<model>X100)$");

        var candidate = Assert.Single(Engine().Detect("ignored\nVendorA Network OS 7.2 Model X100\nignored", new[] { rule }).Candidates);

        Assert.Equal("VendorA Network OS 7.2 Model X100", candidate.Evidence);
    }

    [Fact]
    public void Windows_crlf_transcript_preserves_each_matched_line_as_exact_evidence()
    {
        var rule = Rule(@"^(?<vendor>VendorA) Network OS (?<version>7\.2) Model (?<model>X100)$");
        var transcript = "ignored\r\nVendorA Network OS 7.2 Model X100\r\nignored";

        var candidate = Assert.Single(Engine().Detect(transcript, new[] { rule }).Candidates);

        Assert.Equal("VendorA Network OS 7.2 Model X100", candidate.Evidence);
    }

    [Fact]
    public void One_rule_returns_each_distinct_product_match_with_its_exact_evidence()
    {
        var rule = Rule(@"^(?<vendor>VendorA) Network OS (?<version>[0-9.]+) Model (?<model>X[0-9]+)$");
        var transcript = "VendorA Network OS 7.2 Model X100\nVendorA Network OS 8.1 Model X200";

        var result = Engine().Detect(transcript, new[] { rule });

        Assert.True(result.RequiresUserConfirmation);
        Assert.Equal(new[] { "X100", "X200" }, result.Candidates.Select(candidate => candidate.Model));
        Assert.Equal(
            new[]
            {
                "VendorA Network OS 7.2 Model X100",
                "VendorA Network OS 8.1 Model X200"
            },
            result.Candidates.Select(candidate => candidate.Evidence));
    }

    [Fact]
    public void Detection_does_not_depend_on_later_rule_collection_mutation_and_output_is_immutable()
    {
        var rules = new List<IdentificationRule> { Rule(DefaultPattern) };
        var result = Engine().Detect("VendorA Network OS 7.2 Model X100", rules);
        rules.Clear();

        var candidates = Assert.IsAssignableFrom<IList<DetectionCandidate>>(result.Candidates);

        Assert.Single(candidates);
        Assert.Throws<NotSupportedException>(() => candidates[0] = candidates[0]);
    }

    [Fact]
    public void Detect_rejects_null_or_blank_transcripts_and_invalid_rule_collections()
    {
        var engine = Engine();

        Assert.Throws<ArgumentNullException>(() => engine.Detect(null!, Rules()));
        Assert.Throws<ArgumentException>(() => engine.Detect(" ", Rules()));
        Assert.Throws<ArgumentNullException>(() => engine.Detect("transcript", null!));
        Assert.Throws<ArgumentException>(() => engine.Detect("transcript", new IdentificationRule[] { null! }));
    }

    [Fact]
    public void Empty_rule_collection_returns_an_unknown_result_for_manual_confirmation()
    {
        var result = Engine().Detect("VendorA Network OS 7.2 Model X100", Array.Empty<IdentificationRule>());

        Assert.True(result.RequiresUserConfirmation);
        Assert.Empty(result.Candidates);
    }

    private const string DefaultPattern = @"^(?<vendor>VendorA) (?<productFamily>Network OS) (?<version>7\.2) Model (?<model>X100)$";
    private const string VerifiedSource = "urn:assessment-tool:test-fixture";

    private static DetectionEngine Engine()
    {
        return new DetectionEngine();
    }

    private static IReadOnlyList<IdentificationRule> Rules()
    {
        return new[] { Rule(DefaultPattern) };
    }

    private static IdentificationRule Rule(string pattern)
    {
        return IdentificationRule.CreateVerified(TargetCategory.NetworkDevice, pattern, 0.95, VerifiedSource);
    }
}
