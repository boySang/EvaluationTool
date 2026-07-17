using System;
using System.Linq;
using System.Reflection;
using System.Text;
using AssessmentTool.Core.Commands;
using Xunit;

namespace AssessmentTool.Core.Tests.Commands;

public sealed class CommandDraftImporterTests
{
    [Fact]
    public void Import_never_creates_executable_content_and_ignores_trusted_claims()
    {
        var result = Import(ValidJson("show version"));

        Assert.True(result.IsPendingReview);
        Assert.False(result.IsExecutable);
        Assert.False(Assert.Single(result.Commands).IsExecutable);
        Assert.Equal(64, result.RawSha256.Length);
        Assert.Contains(result.Findings, finding => finding.Code == "DRAFT_NEVER_EXECUTABLE");
        Assert.Contains(result.Findings, finding => finding.Code == "DECLARED_VERIFICATION_IGNORED");
        Assert.Contains(result.Findings, finding => finding.Code == "DECLARED_READ_ONLY_IGNORED");
        Assert.DoesNotContain(typeof(CommandPack), result.GetType().GetProperties().Select(property => property.PropertyType));
        Assert.DoesNotContain(typeof(AssessmentTool.Core.Domain.CommandDefinition),
            result.GetType().GetProperties().Select(property => property.PropertyType));
    }

    [Theory]
    [InlineData("configure terminal")]
    [InlineData("rm -rf /tmp/test")]
    [InlineData("UPDATE users SET enabled = 0")]
    [InlineData("docker stop mysql")]
    [InlineData("echo unsafe > /tmp/output")]
    [InlineData("Set-Service sshd -StartupType Disabled")]
    public void Import_flags_obvious_mutation_as_blocker(string commandText)
    {
        var result = Import(ValidJson(commandText));

        Assert.True(result.HasBlockers);
        Assert.Contains(result.Findings, finding => finding.Code == "OBVIOUS_MUTATION");
    }

    [Fact]
    public void Import_rejects_files_over_one_megabyte_before_json_parsing()
    {
        var bytes = new byte[CommandDraftImporter.MaximumImportBytes + 1];

        var error = Assert.Throws<CommandDraftImportException>(() =>
            new CommandDraftImporter().Import(bytes, "commands.json", DateTimeOffset.UtcNow));

        Assert.Contains("1 MB", error.Message);
    }

    [Fact]
    public void Import_rejects_duplicate_json_properties()
    {
        const string json = "{\"id\":\"a\",\"id\":\"b\",\"name\":\"草稿\",\"version\":\"1.0.0\",\"commands\":[]}";

        Assert.Throws<CommandDraftImportException>(() => Import(json));
    }

    [Fact]
    public void Import_accepts_utf8_bom_but_hashes_original_bytes()
    {
        var body = Encoding.UTF8.GetBytes(ValidJson("show version"));
        var bytes = Encoding.UTF8.GetPreamble().Concat(body).ToArray();

        var result = new CommandDraftImporter().Import(bytes, @"C:\temp\draft.json", DateTimeOffset.UtcNow);

        Assert.Equal("draft.json", result.SourceFileName);
        Assert.Single(result.Commands);
        Assert.Equal(64, result.RawSha256.Length);
    }

    [Fact]
    public void Draft_contract_cannot_expose_formal_executable_command_types()
    {
        var forbidden = new[]
        {
            typeof(CommandPack),
            typeof(AssessmentTool.Core.Domain.CommandDefinition)
        };
        var draftTypes = new[]
        {
            typeof(CommandDraftImporter),
            typeof(CommandDraftImportResult),
            typeof(CommandDraftItem),
            typeof(CommandDraftFinding)
        };

        foreach (var type in draftTypes)
        {
            var exposedTypes = type.GetMembers(BindingFlags.Instance | BindingFlags.Public)
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
                })
                .ToArray();
            Assert.All(forbidden, forbiddenType =>
                Assert.DoesNotContain(exposedTypes, exposedType =>
                    exposedType == forbiddenType
                    || (exposedType.IsGenericType
                        && exposedType.GetGenericArguments().Contains(forbiddenType))));
        }
    }

    private static CommandDraftImportResult Import(string json)
    {
        return new CommandDraftImporter().Import(
            Encoding.UTF8.GetBytes(json),
            "commands.json",
            new DateTimeOffset(2026, 7, 17, 8, 0, 0, TimeSpan.Zero));
    }

    private static string ValidJson(string commandText)
    {
        return "{"
            + "\"id\":\"draft-pack\","
            + "\"name\":\"用户草稿\","
            + "\"version\":\"1.0.0\","
            + "\"commands\":[{"
            + "\"id\":\"show-version\","
            + "\"title\":\"版本信息\","
            + "\"targetCategory\":\"Server\","
            + "\"commandText\":" + Newtonsoft.Json.JsonConvert.ToString(commandText) + ","
            + "\"verificationStatus\":\"Verified\","
            + "\"isReadOnly\":true,"
            + "\"riskLevel\":\"Low\""
            + "}]}";
    }
}
