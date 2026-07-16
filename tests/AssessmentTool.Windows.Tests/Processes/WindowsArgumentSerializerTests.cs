using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using AssessmentTool.Windows.Processes;
using Xunit;

namespace AssessmentTool.Windows.Tests.Processes;

public sealed class WindowsArgumentSerializerTests
{
    private const string TrustedArgv0 = "AssessmentToolTrustedRunner.exe";

    [Theory]
    [InlineData("", "\"\"")]
    [InlineData("plain", "plain")]
    [InlineData(@"tools\客户资料\key file.ppk", "\"tools\\客户资料\\key file.ppk\"")]
    [InlineData("value=\"quoted\"", "\"value=\\\"quoted\\\"\"")]
    [InlineData("prefix\\\"suffix", "\"prefix\\\\\\\"suffix\"")]
    [InlineData("prefix\\\\\"suffix", "\"prefix\\\\\\\\\\\"suffix\"")]
    [InlineData("folder with spaces\\", "\"folder with spaces\\\\\"")]
    [InlineData("[fe80::1%12]:22", "[fe80::1%12]:22")]
    [InlineData("ssh-ed25519 255 SHA256:AbCdEf0123456789", "\"ssh-ed25519 255 SHA256:AbCdEf0123456789\"")]
    [InlineData("device\U0001F600", "device\U0001F600")]
    [InlineData("Cafe\u0301", "Cafe\u0301")]
    [InlineData("alpha\u2003beta", "\"alpha\u2003beta\"")]
    public void Known_windows_argument_encoding_vectors_are_exact(string argumentToken, string expected)
    {
        Assert.Equal(expected, WindowsArgumentSerializer.Serialize(new[] { argumentToken }));
    }

    [Fact]
    public void Multiple_argument_tokens_preserve_order_without_treating_argv0_as_input()
    {
        var argumentTokens = new[] { "-batch", "example.test", "echo readonly" };

        var serialized = WindowsArgumentSerializer.Serialize(argumentTokens);

        Assert.Equal("-batch example.test \"echo readonly\"", serialized);
        Assert.DoesNotContain(TrustedArgv0, serialized);
    }

    [Fact]
    public void Empty_argument_token_list_returns_empty_string()
    {
        Assert.Equal(
            string.Empty,
            WindowsArgumentSerializer.Serialize(argumentTokens: Array.Empty<string>()));
    }

    [Fact]
    public void Serializer_preserves_tokens_for_direct_process_launch()
    {
        Assert.Equal("&|<>$`", WindowsArgumentSerializer.Serialize(new[] { "&|<>$`" }));
    }

    [Fact]
    public void Null_argument_token_list_is_rejected()
    {
        Assert.Throws<ArgumentNullException>(() =>
            WindowsArgumentSerializer.Serialize(argumentTokens: null!));
    }

    [Fact]
    public void Null_argument_token_is_rejected()
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsArgumentSerializer.Serialize(new[] { "valid", null! }));
    }

    [Theory]
    [InlineData("before\0after")]
    [InlineData("before\rafter")]
    [InlineData("before\nafter")]
    public void Nul_cr_and_lf_are_rejected(string argumentToken)
    {
        Assert.Throws<ArgumentException>(() =>
            WindowsArgumentSerializer.Serialize(new[] { argumentToken }));
    }

    [Fact]
    public void Serializer_contract_accepts_only_argv1_and_later_argument_tokens()
    {
        var serialize = typeof(WindowsArgumentSerializer).GetMethod(
            nameof(WindowsArgumentSerializer.Serialize),
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(serialize);
        Assert.Equal(typeof(string), serialize!.ReturnType);
        var parameter = Assert.Single(serialize.GetParameters());
        Assert.Equal("argumentTokens", parameter.Name);
        Assert.Equal(typeof(IReadOnlyList<string>), parameter.ParameterType);
    }

    [Fact]
    public void Serializer_contract_has_no_process_starting_surface()
    {
        var serializerType = typeof(WindowsArgumentSerializer);
        var processTypes = new[] { typeof(Process), typeof(ProcessStartInfo) };
        var declaredMethods = serializerType.GetMethods(
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.DeclaredOnly);

        Assert.False(serializerType.IsPublic);
        Assert.True(serializerType.IsAbstract && serializerType.IsSealed);
        Assert.Empty(serializerType.GetMethods(BindingFlags.Public | BindingFlags.Static));
        Assert.DoesNotContain(serializerType.GetFields(
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance),
            field => processTypes.Contains(field.FieldType));
        Assert.DoesNotContain(declaredMethods, method =>
            processTypes.Contains(method.ReturnType)
            || method.GetParameters().Any(parameter => processTypes.Contains(parameter.ParameterType)));
    }

    [Fact]
    [Trait("Category", "Windows")]
    public void Command_line_to_argv_w_round_trips_argv1_and_later_on_windows()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            return;
        }

        var argumentTokens = new[]
        {
            string.Empty,
            "plain",
            @"tools\客户资料\key file.ppk",
            "value=\"quoted\"",
            "prefix\\\"suffix",
            "prefix\\\\\"suffix",
            "folder with spaces\\",
            "[fe80::1%12]:22",
            "ssh-ed25519 255 SHA256:AbCdEf0123456789",
            "&|<>$`",
            "device\U0001F600",
            "Cafe\u0301",
            "alpha\u2003beta"
        };
        var serializedArguments = WindowsArgumentSerializer.Serialize(argumentTokens);
        var commandLine = TrustedArgv0 + " " + serializedArguments;

        var parsed = ParseWithCommandLineToArgvW(commandLine);

        Assert.Equal(TrustedArgv0, parsed[0]);
        Assert.Equal(argumentTokens, parsed.Skip(1));
    }

    private static IReadOnlyList<string> ParseWithCommandLineToArgvW(string commandLine)
    {
        var argumentsPointer = CommandLineToArgvW(commandLine, out var argumentCount);
        Assert.NotEqual(IntPtr.Zero, argumentsPointer);

        try
        {
            var parsed = new List<string>(argumentCount);
            for (var index = 0; index < argumentCount; index++)
            {
                var argumentPointer = Marshal.ReadIntPtr(argumentsPointer, index * IntPtr.Size);
                var argument = Marshal.PtrToStringUni(argumentPointer);
                Assert.NotNull(argument);
                parsed.Add(argument!);
            }

            return parsed;
        }
        finally
        {
            Assert.Equal(IntPtr.Zero, LocalFree(argumentsPointer));
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
