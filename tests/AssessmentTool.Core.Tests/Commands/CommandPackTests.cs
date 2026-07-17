using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AssessmentTool.Core.Tests.Commands;

public sealed class CommandPackTests
{
    [Fact]
    public void Loader_verifies_the_expected_sha256_over_exact_utf8_json_bytes()
    {
        var jsonBytes = Utf8(PackJson());

        var pack = new CommandPackLoader().Load(jsonBytes, Sha256(jsonBytes));

        Assert.Equal(Sha256(jsonBytes), pack.Sha256);
    }

    [Fact]
    public void Loader_input_snapshot_is_isolated_from_later_source_array_mutation()
    {
        var source = Utf8(PackJson());
        var expectedSha256 = Sha256(source);
        var snapshot = CommandPackLoader.CaptureInputSnapshot(source);

        source[0] = (byte)'[';

        var pack = new CommandPackLoader().Load(snapshot, expectedSha256);
        Assert.NotSame(source, snapshot);
        Assert.Equal("pack-1", pack.Id);
        Assert.Equal(expectedSha256, pack.Sha256);
    }

    [Fact]
    public void Loader_exposes_only_the_byte_array_and_expected_hash_api()
    {
        var load = Assert.Single(typeof(CommandPackLoader).GetMethods(), method => method.Name == "Load");

        Assert.Equal(
            new[] { typeof(byte[]), typeof(string) },
            load.GetParameters().Select(parameter => parameter.ParameterType));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-sha256")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")]
    public void Loader_rejects_a_malformed_expected_sha256(string expectedSha256)
    {
        var jsonBytes = Utf8(PackJson());
        var error = Assert.Throws<CommandPackException>(() =>
            new CommandPackLoader().Load(jsonBytes, expectedSha256));

        Assert.Contains("SHA-256", error.Message);
    }

    [Fact]
    public void Loader_rejects_a_sha256_that_does_not_match_the_exact_json_bytes()
    {
        var jsonBytes = Utf8(PackJson());

        var error = Assert.Throws<CommandPackException>(() =>
            new CommandPackLoader().Load(jsonBytes, new string('0', 64)));

        Assert.Contains("SHA-256", error.Message);
    }

    [Fact]
    public void Loader_rejects_invalid_utf8_after_hashing_the_original_bytes()
    {
        var jsonBytes = new byte[] { 0x7b, 0x22, 0x80, 0x22, 0x3a, 0x31, 0x7d };

        var error = Assert.Throws<CommandPackException>(() =>
            new CommandPackLoader().Load(jsonBytes, Sha256(jsonBytes)));

        Assert.Contains("UTF-8", error.Message);
    }

    [Fact]
    public void Loader_rejects_utf8_bom_for_canonical_command_packs()
    {
        var jsonBytes = Encoding.UTF8.GetPreamble().Concat(Utf8(PackJson())).ToArray();

        var error = Assert.Throws<CommandPackException>(() =>
            new CommandPackLoader().Load(jsonBytes, Sha256(jsonBytes)));

        Assert.Contains("BOM", error.Message);
    }

    [Fact]
    public void Loader_rejects_unknown_json_fields()
    {
        var json = PackJson().Replace("\"commands\": [", "\"unexpected\": true,\n  \"commands\": [");

        var error = Assert.Throws<CommandPackException>(() =>
            LoadJson(json));

        Assert.Contains("未知", error.Message);
    }

    [Fact]
    public void Loader_rejects_package_property_names_with_wrong_case_before_binding()
    {
        var json = PackJson().Replace("\"id\": \"pack-1\"", "\"Id\": \"pack-1\"");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("字段", error.Message);
    }

    [Fact]
    public void Loader_rejects_string_is_read_only_values_before_binding()
    {
        var json = PackJson().Replace("\"isReadOnly\": true", "\"isReadOnly\": \"true\"");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("JSON 类型", error.Message);
    }

    [Fact]
    public void Loader_rejects_string_timeout_values_before_binding()
    {
        var json = PackJson().Replace("\"timeoutSeconds\": 30", "\"timeoutSeconds\": \"30\"");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("JSON 类型", error.Message);
    }

    [Fact]
    public void Loader_rejects_floating_point_timeout_values_before_binding()
    {
        var json = PackJson().Replace("\"timeoutSeconds\": 30", "\"timeoutSeconds\": 30.5");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("JSON 类型", error.Message);
    }

    [Fact]
    public void Loader_rejects_non_array_commands_before_binding()
    {
        var document = JObject.Parse(PackJson());
        var commands = Assert.IsType<JArray>(document["commands"]);
        document["commands"] = commands[0]!.DeepClone();

        var error = Assert.Throws<CommandPackException>(() => LoadJson(document.ToString()));

        Assert.Contains("JSON 类型", error.Message);
    }

    [Fact]
    public void Loader_rejects_null_required_command_values_before_binding()
    {
        var json = PackJson().Replace("\"title\": \"查询信息\"", "\"title\": null");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("JSON 类型", error.Message);
    }

    [Fact]
    public void Loader_rejects_duplicate_json_fields_case_insensitively_at_pack_level()
    {
        var json = PackJson().Replace("\"id\": \"pack-1\",", "\"id\": \"pack-1\",\n  \"ID\": \"pack-2\",");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("重复", error.Message);
    }

    [Fact]
    public void Loader_rejects_duplicate_json_fields_case_insensitively_in_command_objects()
    {
        var json = PackJson().Replace("\"title\": \"查询信息\",", "\"title\": \"查询信息\",\n      \"TITLE\": \"覆盖标题\",");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("重复", error.Message);
    }

    [Fact]
    public void Command_pack_commands_do_not_allow_i_list_replacement()
    {
        var source = new[] { Assert.Single(LoadJson(PackJson()).Commands) };
        var pack = new CommandPack("pack", "Pack", "1.0.0", "https://example.com/commands", "hash", source);
        var commands = Assert.IsAssignableFrom<IList<CommandDefinition>>(pack.Commands);

        Assert.Throws<NotSupportedException>(() => commands[0] = source[0]);
    }

    [Fact]
    public void Command_pack_commands_are_isolated_from_source_array_mutation()
    {
        var original = Assert.Single(LoadJson(PackJson()).Commands);
        var replacement = Assert.Single(LoadJson(PackJson(commandId: "cmd-2")).Commands);
        var source = new[] { original };
        var pack = new CommandPack("pack", "Pack", "1.0.0", "https://example.com/commands", "hash", source);

        source[0] = replacement;

        Assert.Same(original, Assert.Single(pack.Commands));
    }

    [Fact]
    public void Command_pack_subset_preserves_requested_order_and_metadata()
    {
        var first = Assert.Single(LoadJson(PackJson(commandId: "cmd-1")).Commands);
        var second = Assert.Single(LoadJson(PackJson(commandId: "cmd-2")).Commands);
        var pack = new CommandPack(
            "pack",
            "Pack",
            "1.0.0",
            "https://example.com/commands",
            "hash",
            new[] { first, second });

        var subset = pack.SelectCommands(new[] { "cmd-2", "cmd-1" });

        Assert.Equal(new[] { "cmd-2", "cmd-1" }, subset.Commands.Select(command => command.Id));
        Assert.Equal(pack.Id, subset.Id);
        Assert.Equal(pack.Version, subset.Version);
        Assert.Equal(pack.Sha256, subset.Sha256);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("")]
    public void Command_pack_subset_rejects_unknown_or_blank_ids(string commandId)
    {
        var command = Assert.Single(LoadJson(PackJson(commandId: "cmd-1")).Commands);
        var pack = new CommandPack(
            "pack",
            "Pack",
            "1.0.0",
            "https://example.com/commands",
            "hash",
            new[] { command });

        Assert.Throws<ArgumentException>(() => pack.SelectCommands(new[] { commandId }));
    }

    [Fact]
    public void Command_pack_subset_rejects_duplicate_ids()
    {
        var command = Assert.Single(LoadJson(PackJson(commandId: "cmd-1")).Commands);
        var pack = new CommandPack(
            "pack",
            "Pack",
            "1.0.0",
            "https://example.com/commands",
            "hash",
            new[] { command });

        Assert.Throws<ArgumentException>(() => pack.SelectCommands(new[] { "cmd-1", "cmd-1" }));
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://example.com/commands")]
    [InlineData("urn:other:test-fixture")]
    public void Loader_rejects_an_untrusted_official_source(string officialSource)
    {
        var json = PackJson(officialSource: officialSource);

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Fact]
    public void Loader_accepts_the_reserved_test_fixture_source()
    {
        var json = PackJson(
            officialSource: "urn:assessment-tool:test-fixture",
            vendor: "AssessmentTool.TestFixture",
            commandOfficialSource: "urn:assessment-tool:test-fixture");

        var pack = LoadJson(json);

        Assert.Equal("urn:assessment-tool:test-fixture", pack.OfficialSource);
        Assert.Equal("urn:assessment-tool:test-fixture", Assert.Single(pack.Commands).OfficialSource);
    }

    [Fact]
    public void Loader_rejects_a_reserved_package_source_when_any_command_is_not_a_test_fixture()
    {
        var json = PackJson(
            officialSource: "urn:assessment-tool:test-fixture",
            vendor: "AssessmentTool.TestFixture",
            secondCommand: CommandJson("cmd-2", "hostname"));

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("AssessmentTool.TestFixture", error.Message);
    }

    [Fact]
    public void Loader_rejects_a_pack_without_a_version()
    {
        var json = PackJson(version: " ");

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("01")]
    [InlineData("999")]
    [InlineData("verified")]
    public void Loader_rejects_non_exact_named_enum_tokens(string verificationStatus)
    {
        var json = PackJson(verificationStatus: verificationStatus);

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Fact]
    public void Loader_rejects_raw_numeric_enum_values()
    {
        var json = PackJson().Replace("\"riskLevel\": \"Low\"", "\"riskLevel\": 0");

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Theory]
    [InlineData("0.0.0")]
    [InlineData("10.20.30")]
    public void Loader_accepts_strict_semver_core_pack_versions(string version)
    {
        var pack = LoadJson(PackJson(version: version));

        Assert.Equal(version, pack.Version);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("1.0")]
    [InlineData("01.0.0")]
    [InlineData("1.01.0")]
    [InlineData("1.0.00")]
    [InlineData("1.0.0-alpha")]
    [InlineData("1.0.0+build")]
    [InlineData("1.0.0.0")]
    [InlineData("-1.0.0")]
    public void Loader_rejects_pack_versions_that_are_not_strict_semver_core(string version)
    {
        Assert.Throws<CommandPackException>(() => LoadJson(PackJson(version: version)));
    }

    [Fact]
    public void Loader_rejects_duplicate_command_ids()
    {
        var json = PackJson(secondCommand: CommandJson("cmd-1", "hostname"));

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Theory]
    [InlineData("Pending")]
    [InlineData("Rejected")]
    public void Loader_rejects_a_pack_with_an_unverified_command(string verificationStatus)
    {
        var json = PackJson(verificationStatus: verificationStatus);

        var error = Assert.Throws<CommandPackException>(() =>
            LoadJson(json));

        Assert.Contains("正式命令包只能包含已验证命令", error.Message);
    }

    [Fact]
    public void Loader_rejects_a_non_read_only_command()
    {
        var json = PackJson(isReadOnly: false);

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Fact]
    public void Loader_rejects_a_command_that_the_safety_policy_rejects()
    {
        var json = PackJson(commandText: "configure terminal");

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Fact]
    public void Loader_rejects_a_command_with_missing_required_metadata()
    {
        var document = JObject.Parse(PackJson());
        var commands = Assert.IsType<JArray>(document["commands"]);
        var command = Assert.IsType<JObject>(commands[0]);
        Assert.True(command.Remove("accountRequirement"));

        Assert.Throws<CommandPackException>(() => LoadJson(document.ToString()));
    }

    [Fact]
    public void Loader_preserves_per_command_verification_date_and_official_source()
    {
        var pack = LoadJson(PackJson(
            verificationDate: "2025-02-03",
            commandOfficialSource: "https://example.com/commands/uname"));

        var command = Assert.Single(pack.Commands);
        Assert.Equal(new DateTime(2025, 2, 3), command.VerificationDate);
        Assert.Equal("https://example.com/commands/uname", command.OfficialSource);
    }

    [Theory]
    [InlineData("")]
    [InlineData("2025-2-03")]
    [InlineData("2025-02-3")]
    [InlineData("2025-02-30")]
    [InlineData("not-a-date")]
    public void Loader_rejects_non_iso_verification_dates(string verificationDate)
    {
        Assert.Throws<CommandPackException>(() => LoadJson(PackJson(verificationDate: verificationDate)));
    }

    [Fact]
    public void Loader_rejects_a_future_verification_date()
    {
        var futureDate = DateTime.UtcNow.Date.AddDays(1).ToString("yyyy-MM-dd");

        Assert.Throws<CommandPackException>(() => LoadJson(PackJson(verificationDate: futureDate)));
    }

    [Theory]
    [InlineData("http://example.com/commands/uname")]
    [InlineData("urn:other:source")]
    public void Loader_rejects_untrusted_per_command_official_sources(string commandOfficialSource)
    {
        Assert.Throws<CommandPackException>(() =>
            LoadJson(PackJson(commandOfficialSource: commandOfficialSource)));
    }

    [Fact]
    public void Loader_rejects_the_reserved_command_source_for_a_non_fixture_vendor()
    {
        Assert.Throws<CommandPackException>(() =>
            LoadJson(PackJson(commandOfficialSource: "urn:assessment-tool:test-fixture")));
    }

    [Theory]
    [InlineData("https://example.com/commands/uname")]
    [InlineData("urn:assessment-tool:test-fixture")]
    public void Loader_rejects_a_test_fixture_vendor_in_an_https_package(string commandOfficialSource)
    {
        var json = PackJson(
            vendor: "AssessmentTool.TestFixture",
            commandOfficialSource: commandOfficialSource);

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("测试", error.Message);
    }

    [Fact]
    public void Loader_rejects_an_https_package_when_any_command_uses_the_test_fixture_vendor()
    {
        var json = PackJson(
            secondCommand: CommandJson(
                "cmd-2",
                "hostname",
                vendor: "AssessmentTool.TestFixture"));

        Assert.Throws<CommandPackException>(() => LoadJson(json));
    }

    [Theory]
    [InlineData("assessmenttool.testfixture")]
    [InlineData("AssessmentTool.testFixture")]
    public void Loader_rejects_test_fixture_vendor_case_variants_in_an_https_package(string vendor)
    {
        var json = PackJson(vendor: vendor);

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("规范拼写", error.Message);
    }

    [Theory]
    [InlineData("assessmenttool.testfixture")]
    [InlineData("AssessmentTool.testFixture")]
    public void Loader_rejects_noncanonical_test_fixture_vendor_case_variants_in_a_test_package(string vendor)
    {
        var json = PackJson(
            officialSource: "urn:assessment-tool:test-fixture",
            vendor: vendor,
            commandOfficialSource: "urn:assessment-tool:test-fixture");

        var error = Assert.Throws<CommandPackException>(() => LoadJson(json));

        Assert.Contains("规范拼写", error.Message);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("X1000")]
    [InlineData("X100*")]
    public void Loader_accepts_explicit_model_range_rules(string modelRange)
    {
        Assert.Equal(modelRange, Assert.Single(LoadJson(PackJson(modelRange: modelRange)).Commands).ModelRange);
    }

    [Theory]
    [InlineData("*X100")]
    [InlineData("X*100")]
    [InlineData("X100**")]
    [InlineData("**")]
    public void Loader_rejects_malformed_model_range_wildcards(string modelRange)
    {
        Assert.Throws<CommandPackException>(() => LoadJson(PackJson(modelRange: modelRange)));
    }

    [Fact]
    public void Matcher_public_api_requires_the_full_detection_result()
    {
        var match = Assert.Single(typeof(CommandMatcher).GetMethods(), method => method.Name == "Match");

        Assert.Equal(
            new[] { typeof(CommandPack), typeof(DetectionResult) },
            match.GetParameters().Select(parameter => parameter.ParameterType));
    }

    [Fact]
    public void Matcher_prefers_exact_vendor_family_and_version()
    {
        var json = ExactAndGenericPackJson();
        var pack = LoadJson(json);
        var target = new DetectionCandidate(
            TargetCategory.NetworkDevice,
            "VendorA",
            "FamilyX",
            "X1000",
            "7.2",
            "fixture",
            0.98);

        var commands = new CommandMatcher().Match(pack, ConfirmedDetection(target));

        Assert.Equal("vendor-a-family-x-7-version", commands[0].Id);
    }

    [Fact]
    public void Matcher_preserves_pack_order_for_commands_with_equal_specificity()
    {
        var json = PackJson(
            commandText: "hostname",
            commandId: "second-in-pack",
            secondCommand: CommandJson("first-in-pack", "uname -a"));
        var pack = LoadJson(json);
        var target = new DetectionCandidate(TargetCategory.Server, "Linux", "Linux", null, "6.1", "fixture", 1.0);

        var commands = new CommandMatcher().Match(pack, ConfirmedDetection(target));

        Assert.Equal(new[] { "second-in-pack", "first-in-pack" }, commands.Select(command => command.Id));
    }

    [Fact]
    public void Matcher_matches_family_x_and_x1000_before_wildcard_and_fallback_rules()
    {
        var json = PackJson(
            targetCategory: "NetworkDevice",
            commandId: "category-generic",
            commandText: "show version",
            secondCommand: CommandJson("vendor-only", "show version", targetCategory: "NetworkDevice", vendor: "VendorA") + ",\n    " +
                CommandJson("family-only", "show version", targetCategory: "NetworkDevice", productFamily: "FamilyX") + ",\n    " +
                CommandJson("prefix-model", "show version", targetCategory: "NetworkDevice", productFamily: "FamilyX", modelRange: "X100*") + ",\n    " +
                CommandJson("exact-model", "show version", targetCategory: "NetworkDevice", productFamily: "FamilyX", modelRange: "X1000"));
        var pack = LoadJson(json);
        var target = new DetectionCandidate(TargetCategory.NetworkDevice, "VendorA", "FamilyX", "x1000", "1.0", "fixture", 1.0);

        var commands = new CommandMatcher().Match(pack, ConfirmedDetection(target));

        Assert.Equal(
            new[] { "exact-model", "prefix-model", "family-only", "vendor-only", "category-generic" },
            commands.Select(command => command.Id));
    }

    [Fact]
    public void Matcher_excludes_commands_whose_model_range_does_not_match_target_model()
    {
        var pack = LoadJson(PackJson(modelRange: "X100*"));
        var target = new DetectionCandidate(TargetCategory.Server, null, "FamilyX", "Y2000", "1.0", "fixture", 1.0);

        Assert.Empty(new CommandMatcher().Match(pack, ConfirmedDetection(target)));
    }

    [Fact]
    public void Matcher_excludes_commands_whose_product_family_does_not_match_target_family()
    {
        var pack = LoadJson(PackJson(productFamily: "FamilyX"));
        var target = new DetectionCandidate(TargetCategory.Server, null, "FamilyY", "X1000", "1.0", "fixture", 1.0);

        Assert.Empty(new CommandMatcher().Match(pack, ConfirmedDetection(target)));
    }

    [Fact]
    public void Matcher_allows_only_wildcard_model_rules_when_target_model_is_unknown()
    {
        var json = PackJson(
            productFamily: "FamilyX",
            commandId: "wildcard-model",
            secondCommand: CommandJson("prefix-model", "hostname", productFamily: "FamilyX", modelRange: "X100*") + ",\n    " +
                CommandJson("exact-model", "hostname", productFamily: "FamilyX", modelRange: "X1000"));
        var target = new DetectionCandidate(TargetCategory.Server, null, "FamilyX", null, "1.0", "fixture", 1.0);

        var commands = new CommandMatcher().Match(LoadJson(json), ConfirmedDetection(target));

        Assert.Equal(new[] { "wildcard-model" }, commands.Select(command => command.Id));
    }

    [Fact]
    public void Matcher_uses_inclusive_numeric_version_boundaries_without_semantic_version_claims()
    {
        var json = PackJson(
            targetCategory: "NetworkDevice",
            vendor: "VendorA",
            productFamily: "FamilyX",
            minimumVersion: "7.0",
            maximumVersion: "7.2");
        var pack = LoadJson(json);

        var atMinimum = new DetectionCandidate(TargetCategory.NetworkDevice, "VendorA", "FamilyX", "X1000", "7.0", "fixture", 1.0);
        var atMaximum = new DetectionCandidate(TargetCategory.NetworkDevice, "VendorA", "FamilyX", "X1000", "7.2", "fixture", 1.0);
        var aboveMaximum = new DetectionCandidate(TargetCategory.NetworkDevice, "VendorA", "FamilyX", "X1000", "7.2.1", "fixture", 1.0);
        var prerelease = new DetectionCandidate(TargetCategory.NetworkDevice, "VendorA", "FamilyX", "X1000", "7.2-rc1", "fixture", 1.0);

        Assert.Single(new CommandMatcher().Match(pack, ConfirmedDetection(atMinimum)));
        Assert.Single(new CommandMatcher().Match(pack, ConfirmedDetection(atMaximum)));
        Assert.Empty(new CommandMatcher().Match(pack, ConfirmedDetection(aboveMaximum)));
        Assert.Empty(new CommandMatcher().Match(pack, ConfirmedDetection(prerelease)));
    }

    [Fact]
    public void Matcher_refuses_automatic_or_low_confidence_targets_pending_confirmation()
    {
        var json = PackJson();
        var pack = LoadJson(json);

        var automatic = new DetectionCandidate(TargetCategory.Automatic, "Linux", "Linux", null, "6.1", "fixture", 1.0);
        var lowConfidence = new DetectionCandidate(TargetCategory.Server, "Linux", "Linux", null, "6.1", "fixture", 0.89);

        Assert.Empty(new CommandMatcher().Match(pack, ConfirmedDetection(automatic)));
        Assert.Empty(new CommandMatcher().Match(pack, ConfirmedDetection(lowConfidence)));
    }

    [Fact]
    public void Matcher_refuses_multiple_high_confidence_candidates_pending_confirmation()
    {
        var pack = LoadJson(PackJson());
        var first = new DetectionCandidate(TargetCategory.Server, "Linux", "Linux", null, "6.1", "banner", 0.99);
        var second = new DetectionCandidate(TargetCategory.Server, "Linux", "Linux", null, "6.1", "system info", 0.98);
        var detection = new DetectionResult(new[] { first, second });

        Assert.Empty(new CommandMatcher().Match(pack, detection));
    }

    [Fact]
    public void Built_in_packs_load_with_complete_safe_metadata_and_fixture_vendor_marking()
    {
        var root = FindRepositoryRoot();
        var genericLinuxPath = Path.Combine(root, "command-packs", "builtin", "generic-linux.json");
        var fixturePath = Path.Combine(root, "command-packs", "builtin", "test-network-device.json");
        var schemaPath = Path.Combine(root, "command-packs", "schema", "command-pack.schema.json");

        Assert.True(File.Exists(schemaPath));
        var genericLinuxJson = File.ReadAllBytes(genericLinuxPath);
        var fixtureJson = File.ReadAllBytes(fixturePath);
        var loader = new CommandPackLoader();

        var genericLinux = loader.Load(genericLinuxJson, Sha256(genericLinuxJson));
        var fixture = loader.Load(fixtureJson, Sha256(fixtureJson));

        Assert.All(genericLinux.Commands.Concat(fixture.Commands), command =>
            Assert.True(new CommandSafetyPolicy().Validate(command).Allowed));
        Assert.All(genericLinux.Commands.Concat(fixture.Commands), command =>
            Assert.True(command.VerificationDate <= DateTime.UtcNow.Date));
        Assert.Equal(
            "https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html",
            genericLinux.Commands.Single(command => command.Id == "generic-linux-uname-a").OfficialSource);
        Assert.Equal(
            "https://www.freedesktop.org/software/systemd/man/latest/os-release.html",
            genericLinux.Commands.Single(command => command.Id == "generic-linux-os-release").OfficialSource);
        Assert.Equal(
            "https://man7.org/linux/man-pages/man1/hostname.1.html",
            genericLinux.Commands.Single(command => command.Id == "generic-linux-hostname").OfficialSource);
        Assert.All(fixture.Commands, command => Assert.Equal("AssessmentTool.TestFixture", command.Vendor));
        Assert.All(fixture.Commands, command =>
            Assert.Equal("urn:assessment-tool:test-fixture", command.OfficialSource));
    }

    [Fact]
    public void Schema_requires_test_fixture_vendor_packages_to_use_the_reserved_source()
    {
        var schemaPath = Path.Combine(
            FindRepositoryRoot(),
            "command-packs",
            "schema",
            "command-pack.schema.json");
        var schema = JObject.Parse(File.ReadAllText(schemaPath));
        var reverseRule = schema["allOf"]!
            .Children<JObject>()
            .Single(rule => string.Equals(
                rule.SelectToken("if.properties.commands.contains.properties.vendor.const")?.Value<string>(),
                "AssessmentTool.TestFixture",
                StringComparison.Ordinal));

        Assert.Equal(
            "urn:assessment-tool:test-fixture",
            reverseRule.SelectToken("then.properties.officialSource.const")?.Value<string>());
    }

    private static string PackJson(
        string? officialSource = null,
        string? version = null,
        string? verificationStatus = null,
        bool isReadOnly = true,
        string commandText = "uname -a",
        string commandId = "cmd-1",
        string targetCategory = "Server",
        string? vendor = null,
        string? productFamily = null,
        string? minimumVersion = null,
        string? maximumVersion = null,
        string modelRange = "*",
        string verificationDate = "2025-02-03",
        string commandOfficialSource = "https://example.com/commands/uname",
        string? secondCommand = null)
    {
        return $@"{{
  ""id"": ""pack-1"",
  ""name"": ""Test pack"",
  ""version"": ""{version ?? "1.0.0"}"",
  ""officialSource"": ""{officialSource ?? "https://example.com/commands"}"",
  ""commands"": [
    {CommandJson(commandId, commandText, verificationStatus ?? "Verified", isReadOnly, targetCategory, vendor, productFamily, minimumVersion, maximumVersion, modelRange, verificationDate, commandOfficialSource)}{(secondCommand == null ? string.Empty : ",\n    " + secondCommand)}
  ]
}}";
    }

    private static string ExactAndGenericPackJson()
    {
        return PackJson(
            targetCategory: "NetworkDevice",
            commandId: "category-generic",
            commandText: "show version",
            secondCommand: CommandJson("vendor-only", "show version", targetCategory: "NetworkDevice", vendor: "VendorA") + ",\n    " +
                CommandJson("family-only", "show version", targetCategory: "NetworkDevice", productFamily: "FamilyX") + ",\n    " +
                CommandJson("vendor-a-family-x", "show version", targetCategory: "NetworkDevice", vendor: "VendorA", productFamily: "FamilyX") + ",\n    " +
                CommandJson("vendor-a-family-x-7-version", "show version", targetCategory: "NetworkDevice", vendor: "VendorA", productFamily: "FamilyX", minimumVersion: "7.2", maximumVersion: "7.2"));
    }

    private static string CommandJson(
        string id,
        string commandText,
        string verificationStatus = "Verified",
        bool isReadOnly = true,
        string targetCategory = "Server",
        string? vendor = null,
        string? productFamily = null,
        string? minimumVersion = null,
        string? maximumVersion = null,
        string modelRange = "*",
        string verificationDate = "2025-02-03",
        string officialSource = "https://example.com/commands/uname")
    {
        return $@"{{
      ""id"": ""{id}"",
      ""title"": ""查询信息"",
      ""targetCategory"": ""{targetCategory}"",
      ""commandText"": ""{commandText}"",
      ""verificationStatus"": ""{verificationStatus}"",
      ""isReadOnly"": {isReadOnly.ToString().ToLowerInvariant()},
      ""vendor"": {JsonStringOrNull(vendor)},
      ""productFamily"": {JsonStringOrNull(productFamily)},
      ""minimumVersion"": {JsonStringOrNull(minimumVersion)},
      ""maximumVersion"": {JsonStringOrNull(maximumVersion)},
      ""checkItem"": ""AC-1"",
      ""modelRange"": ""{modelRange}"",
      ""accountRequirement"": ""只读审计账户"",
      ""riskLevel"": ""Low"",
      ""timeoutSeconds"": 30,
      ""pagingBehavior"": ""DisablePaging"",
      ""resultDescription"": ""确认系统信息"",
      ""verificationDate"": ""{verificationDate}"",
      ""officialSource"": ""{officialSource}""
    }}";
    }

    private static string JsonStringOrNull(string? value)
    {
        return value == null ? "null" : "\"" + value + "\"";
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current != null)
        {
            if (File.Exists(Path.Combine(current.FullName, "AssessmentTool.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("无法定位命令包仓库根目录。");
    }

    private static CommandPack LoadJson(string json)
    {
        var jsonBytes = Utf8(json);
        return new CommandPackLoader().Load(jsonBytes, Sha256(jsonBytes));
    }

    private static DetectionResult ConfirmedDetection(DetectionCandidate candidate)
    {
        return new DetectionResult(new[] { candidate });
    }

    private static byte[] Utf8(string json)
    {
        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetBytes(json);
    }

    private static string Sha256(byte[] jsonBytes)
    {
        using var algorithm = SHA256.Create();
        var bytes = algorithm.ComputeHash(jsonBytes);
        return string.Concat(bytes.Select(value => value.ToString("x2")));
    }
}
