using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reflection;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.Services;

public sealed class BuiltinCommandPackCatalog
{
    private const int MaximumCommandPackBytes = 1024 * 1024;
    private const string GenericLinuxPackId = "generic-linux";
    private const string GenericLinuxRelativePath = "command-packs/builtin/generic-linux.json";
    private const string GenericLinuxResourceName = "AssessmentTool.App.CommandPacks.Builtin.GenericLinux.json";
    private const string GenericLinuxSha256 = "89e1fc9b46c9b8afc8d3fe41632c7da6a9d84a41e585038c233c23b56b8189b1";

    private static readonly IReadOnlyList<string> IdentificationIds =
        new ReadOnlyCollection<string>(new[]
        {
            "generic-linux-uname-a",
            "generic-linux-os-release"
        });

    private static readonly IReadOnlyList<string> CollectionIds =
        new ReadOnlyCollection<string>(new[]
        {
            "generic-linux-hostname"
        });

    private readonly string releaseDirectory;
    private readonly Assembly resourceAssembly;

    public BuiltinCommandPackCatalog()
        : this(AppDomain.CurrentDomain.BaseDirectory, typeof(BuiltinCommandPackCatalog).Assembly)
    {
    }

    public BuiltinCommandPackCatalog(string releaseDirectory)
        : this(releaseDirectory, typeof(BuiltinCommandPackCatalog).Assembly)
    {
    }

    internal BuiltinCommandPackCatalog(string releaseDirectory, Assembly resourceAssembly)
    {
        if (string.IsNullOrWhiteSpace(releaseDirectory))
        {
            throw new ArgumentException("发布目录不能为空。", nameof(releaseDirectory));
        }

        this.releaseDirectory = Path.GetFullPath(releaseDirectory);
        this.resourceAssembly = resourceAssembly ?? throw new ArgumentNullException(nameof(resourceAssembly));
    }

    public IReadOnlyList<string> GenericLinuxIdentificationCommandIds => IdentificationIds;

    public IReadOnlyList<string> GenericLinuxCollectionCommandIds => CollectionIds;

    public CommandPack LoadGenericLinux()
    {
        var packBytes = LoadGenericLinuxBytes();
        var pack = new CommandPackLoader().Load(packBytes, GenericLinuxSha256);
        EnsureGenericLinuxLayout(pack);
        return pack;
    }

    public IReadOnlyList<CommandDefinition> SelectGenericLinuxIdentificationCommands(CommandPack pack)
    {
        return SelectCommands(pack, IdentificationIds);
    }

    public IReadOnlyList<CommandDefinition> SelectGenericLinuxCollectionCommands(CommandPack pack)
    {
        return SelectCommands(pack, CollectionIds);
    }

    private byte[] LoadGenericLinuxBytes()
    {
        var releasePath = Path.Combine(
            releaseDirectory,
            GenericLinuxRelativePath.Replace('/', Path.DirectorySeparatorChar));

        if (File.Exists(releasePath))
        {
            try
            {
                using var stream = new FileStream(
                    releasePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 4096,
                    options: FileOptions.SequentialScan);
                return ReadBounded(stream, "发布目录中的通用 Linux 命令包");
            }
            catch (CommandPackException)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException)
            {
                throw new CommandPackException("无法读取发布目录中的通用 Linux 命令包。", exception);
            }
        }

        using var resource = resourceAssembly.GetManifestResourceStream(GenericLinuxResourceName);
        if (resource == null)
        {
            throw new CommandPackException("发布目录和程序集资源中都缺少通用 Linux 命令包。");
        }

        return ReadBounded(resource, "内嵌的通用 Linux 命令包");
    }

    private static byte[] ReadBounded(Stream stream, string description)
    {
        if (stream.CanSeek && stream.Length > MaximumCommandPackBytes)
        {
            throw new CommandPackException(description + "超过允许的最大大小。");
        }

        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var bytesRead = stream.Read(chunk, 0, chunk.Length);
            if (bytesRead == 0)
            {
                break;
            }

            if (buffer.Length + bytesRead > MaximumCommandPackBytes)
            {
                throw new CommandPackException(description + "超过允许的最大大小。");
            }

            buffer.Write(chunk, 0, bytesRead);
        }

        return buffer.ToArray();
    }

    private static IReadOnlyList<CommandDefinition> SelectCommands(
        CommandPack pack,
        IReadOnlyList<string> commandIds)
    {
        EnsureGenericLinuxLayout(pack);
        var commandsById = pack.Commands.ToDictionary(command => command.Id, StringComparer.Ordinal);
        return new ReadOnlyCollection<CommandDefinition>(
            commandIds.Select(commandId => commandsById[commandId]).ToArray());
    }

    private static void EnsureGenericLinuxLayout(CommandPack pack)
    {
        if (pack == null)
        {
            throw new ArgumentNullException(nameof(pack));
        }

        if (!string.Equals(pack.Id, GenericLinuxPackId, StringComparison.Ordinal))
        {
            throw new CommandPackException("命令包不是受支持的通用 Linux 内置命令包。");
        }

        var expectedIds = new HashSet<string>(IdentificationIds.Concat(CollectionIds), StringComparer.Ordinal);
        var actualIds = new HashSet<string>(pack.Commands.Select(command => command.Id), StringComparer.Ordinal);
        if (!expectedIds.SetEquals(actualIds))
        {
            throw new CommandPackException("通用 Linux 内置命令包的命令分类与受信任目录不一致。");
        }
    }
}
