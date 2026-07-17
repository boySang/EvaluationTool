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
    private const string GenericLinuxSha256 = "8e5855b4526dc0a9a74375aed8710e3ccaf04dcc0140a62fc3846599fc43f1b0";
    private const string DatabaseDiscoveryPackId = "database-host-discovery-linux";
    private const string DatabaseDiscoveryRelativePath = "command-packs/builtin/database-host-discovery-linux.json";
    private const string DatabaseDiscoveryResourceName = "AssessmentTool.App.CommandPacks.Builtin.DatabaseHostDiscoveryLinux.json";
    private const string DatabaseDiscoverySha256 = "15ca85ad86624e1e0bfd244b480445614ec39497bf1ecfc869c62922ac4e8761";
    private const string HuaweiVrpPackId = "huawei-vrp";
    private const string HuaweiVrpRelativePath = "command-packs/builtin/huawei-vrp.json";
    private const string HuaweiVrpResourceName = "AssessmentTool.App.CommandPacks.Builtin.HuaweiVrp.json";
    private const string HuaweiVrpSha256 = "ecbef9697e1c39fa9f0e6654dab7f989cb9c5c37a13ebc2d2a2ee25eae165411";
    private const string H3cComwarePackId = "h3c-comware";
    private const string H3cComwareRelativePath = "command-packs/builtin/h3c-comware.json";
    private const string H3cComwareResourceName = "AssessmentTool.App.CommandPacks.Builtin.H3cComware.json";
    private const string H3cComwareSha256 = "c4422bf699583a2abc1bf476c78060580c2ac09ebfbc1bd0d4377a381e449e97";

    private static readonly IReadOnlyList<string> IdentificationIds =
        new ReadOnlyCollection<string>(new[]
        {
            "generic-linux-uname-a",
            "generic-linux-os-release"
        });

    private static readonly IReadOnlyList<string> CollectionIds =
        new ReadOnlyCollection<string>(new[]
        {
            "generic-linux-hostname",
            "generic-linux-login-defs"
        });

    private static readonly IReadOnlyList<string> DatabaseDiscoveryIds =
        new ReadOnlyCollection<string>(new[]
        {
            "database-host-discovery-linux-processes",
            "database-host-discovery-linux-services",
            "database-host-discovery-linux-docker-containers",
            "database-host-discovery-linux-podman-containers"
        });

    private static readonly IReadOnlyList<string> HuaweiVrpIdentificationIds =
        new ReadOnlyCollection<string>(new[] { "huawei-vrp-display-version" });

    private static readonly IReadOnlyList<string> HuaweiVrpCollectionIds =
        new ReadOnlyCollection<string>(new[] { "huawei-vrp-display-aaa-configuration" });

    private static readonly IReadOnlyList<string> H3cComwareIdentificationIds =
        new ReadOnlyCollection<string>(new[] { "h3c-comware-display-version" });

    private static readonly IReadOnlyList<string> H3cComwareCollectionIds =
        new ReadOnlyCollection<string>(new[] { "h3c-comware-display-password-control" });

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

    public IReadOnlyList<string> HuaweiVrpIdentificationCommandIds => HuaweiVrpIdentificationIds;

    public IReadOnlyList<string> H3cComwareIdentificationCommandIds => H3cComwareIdentificationIds;

    public CommandPack LoadGenericLinux()
    {
        var packBytes = LoadPackBytes(
            GenericLinuxRelativePath,
            GenericLinuxResourceName,
            "通用 Linux 命令包");
        var pack = new CommandPackLoader().Load(packBytes, GenericLinuxSha256);
        EnsureGenericLinuxLayout(pack);
        return pack;
    }

    public CommandPack LoadDatabaseHostDiscoveryLinux()
    {
        var packBytes = LoadPackBytes(
            DatabaseDiscoveryRelativePath,
            DatabaseDiscoveryResourceName,
            "Linux 数据库主机发现命令包");
        var pack = new CommandPackLoader().Load(packBytes, DatabaseDiscoverySha256);
        EnsureDatabaseDiscoveryLayout(pack);
        return pack;
    }

    public CommandPack LoadHuaweiVrp()
    {
        var packBytes = LoadPackBytes(
            HuaweiVrpRelativePath,
            HuaweiVrpResourceName,
            "华为 VRP 命令包");
        var pack = new CommandPackLoader().Load(packBytes, HuaweiVrpSha256);
        EnsureHuaweiVrpLayout(pack);
        return pack;
    }

    public CommandPack LoadH3cComware()
    {
        var packBytes = LoadPackBytes(
            H3cComwareRelativePath,
            H3cComwareResourceName,
            "H3C Comware 命令包");
        var pack = new CommandPackLoader().Load(packBytes, H3cComwareSha256);
        EnsureH3cComwareLayout(pack);
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

    public CommandPack CreateGenericLinuxCollectionPack(CommandPack pack)
    {
        EnsureGenericLinuxLayout(pack);
        return pack.SelectCommands(CollectionIds);
    }

    public IReadOnlyList<CommandDefinition> SelectHuaweiVrpIdentificationCommands(CommandPack pack)
    {
        EnsureHuaweiVrpLayout(pack);
        return SelectCommandsUnchecked(pack, HuaweiVrpIdentificationIds);
    }

    public CommandPack CreateHuaweiVrpCollectionPack(CommandPack pack)
    {
        EnsureHuaweiVrpLayout(pack);
        return pack.SelectCommands(HuaweiVrpCollectionIds);
    }

    public IReadOnlyList<CommandDefinition> SelectH3cComwareIdentificationCommands(CommandPack pack)
    {
        EnsureH3cComwareLayout(pack);
        return SelectCommandsUnchecked(pack, H3cComwareIdentificationIds);
    }

    public CommandPack CreateH3cComwareCollectionPack(CommandPack pack)
    {
        EnsureH3cComwareLayout(pack);
        return pack.SelectCommands(H3cComwareCollectionIds);
    }

    private byte[] LoadPackBytes(string relativePath, string resourceName, string description)
    {
        var releasePath = Path.Combine(
            releaseDirectory,
            relativePath.Replace('/', Path.DirectorySeparatorChar));

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
                return ReadBounded(stream, "发布目录中的" + description);
            }
            catch (CommandPackException)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException)
            {
                throw new CommandPackException("无法读取发布目录中的" + description + "。", exception);
            }
        }

        using var resource = resourceAssembly.GetManifestResourceStream(resourceName);
        if (resource == null)
        {
            throw new CommandPackException("发布目录和程序集资源中都缺少" + description + "。");
        }

        return ReadBounded(resource, "内嵌的" + description);
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

    private static IReadOnlyList<CommandDefinition> SelectCommandsUnchecked(
        CommandPack pack,
        IReadOnlyList<string> commandIds)
    {
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

        var definitions = pack.Commands.ToDictionary(command => command.Id, StringComparer.Ordinal);
        if (IdentificationIds.Any(commandId =>
                !string.Equals(definitions[commandId].CheckItem, "IDENTIFY", StringComparison.Ordinal)))
        {
            throw new CommandPackException("通用 Linux 固定识别命令缺少 IDENTIFY 安全标记。");
        }
    }

    private static void EnsureDatabaseDiscoveryLayout(CommandPack pack)
    {
        if (pack == null)
        {
            throw new ArgumentNullException(nameof(pack));
        }

        if (!string.Equals(pack.Id, DatabaseDiscoveryPackId, StringComparison.Ordinal))
        {
            throw new CommandPackException("命令包不是受支持的 Linux 数据库主机发现内置命令包。");
        }

        if (!DatabaseDiscoveryIds.SequenceEqual(pack.Commands.Select(command => command.Id), StringComparer.Ordinal))
        {
            throw new CommandPackException("Linux 数据库主机发现命令包的命令顺序与受信任目录不一致。");
        }
    }

    private static void EnsureHuaweiVrpLayout(CommandPack pack)
    {
        if (pack == null)
        {
            throw new ArgumentNullException(nameof(pack));
        }

        if (!string.Equals(pack.Id, HuaweiVrpPackId, StringComparison.Ordinal))
        {
            throw new CommandPackException("命令包不是受支持的华为 VRP 内置命令包。");
        }

        var expectedIds = HuaweiVrpIdentificationIds.Concat(HuaweiVrpCollectionIds).ToArray();
        if (!expectedIds.SequenceEqual(pack.Commands.Select(command => command.Id), StringComparer.Ordinal)
            || pack.Commands.Any(command => command.TargetCategory != TargetCategory.NetworkDevice
                || !string.Equals(command.Vendor, "Huawei", StringComparison.Ordinal)))
        {
            throw new CommandPackException("华为 VRP 内置命令包的命令顺序或对象边界不正确。");
        }

        if (HuaweiVrpIdentificationIds.Any(commandId =>
            !string.Equals(pack.Commands.Single(command => command.Id == commandId).CheckItem,
                "IDENTIFY",
                StringComparison.Ordinal)))
        {
            throw new CommandPackException("华为 VRP 固定识别命令缺少 IDENTIFY 安全标记。");
        }
    }

    private static void EnsureH3cComwareLayout(CommandPack pack)
    {
        if (pack == null)
        {
            throw new ArgumentNullException(nameof(pack));
        }

        if (!string.Equals(pack.Id, H3cComwarePackId, StringComparison.Ordinal))
        {
            throw new CommandPackException("命令包不是受支持的 H3C Comware 内置命令包。");
        }

        var expectedIds = H3cComwareIdentificationIds.Concat(H3cComwareCollectionIds).ToArray();
        if (!expectedIds.SequenceEqual(pack.Commands.Select(command => command.Id), StringComparer.Ordinal)
            || pack.Commands.Any(command => command.TargetCategory != TargetCategory.NetworkDevice
                || !string.Equals(command.Vendor, "H3C", StringComparison.Ordinal)
                || !string.Equals(command.ProductFamily, "Comware", StringComparison.Ordinal)))
        {
            throw new CommandPackException("H3C Comware 内置命令包的命令顺序或对象边界不正确。");
        }

        if (H3cComwareIdentificationIds.Any(commandId =>
            !string.Equals(pack.Commands.Single(command => command.Id == commandId).CheckItem,
                "IDENTIFY",
                StringComparison.Ordinal)))
        {
            throw new CommandPackException("H3C Comware 固定识别命令缺少 IDENTIFY 安全标记。");
        }
    }
}
