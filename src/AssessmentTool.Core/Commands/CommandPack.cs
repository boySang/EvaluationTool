using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Commands;

public sealed class CommandPack
{
    internal CommandPack(
        string id,
        string name,
        string version,
        string officialSource,
        string sha256,
        IEnumerable<CommandDefinition> commands)
    {
        Id = id;
        Name = name;
        Version = version;
        OfficialSource = officialSource;
        Sha256 = sha256;
        var commandArray = (commands ?? throw new ArgumentNullException(nameof(commands))).ToArray();
        Commands = new ReadOnlyCollection<CommandDefinition>(commandArray);
    }

    public string Id { get; }
    public string Name { get; }
    public string Version { get; }
    public string OfficialSource { get; }
    public string Sha256 { get; }
    public IReadOnlyList<CommandDefinition> Commands { get; }

    public CommandPack SelectCommands(IEnumerable<string> commandIds)
    {
        if (commandIds == null)
        {
            throw new ArgumentNullException(nameof(commandIds));
        }

        var requested = commandIds.ToArray();
        if (requested.Length == 0
            || requested.Any(string.IsNullOrWhiteSpace)
            || requested.Distinct(StringComparer.Ordinal).Count() != requested.Length)
        {
            throw new ArgumentException("命令子集必须包含不重复的有效命令标识。", nameof(commandIds));
        }

        var byId = Commands.ToDictionary(command => command.Id, StringComparer.Ordinal);
        if (requested.Any(commandId => !byId.ContainsKey(commandId)))
        {
            throw new ArgumentException("命令子集包含不属于当前命令包的标识。", nameof(commandIds));
        }

        return new CommandPack(
            Id,
            Name,
            Version,
            OfficialSource,
            Sha256,
            requested.Select(commandId => byId[commandId]));
    }
}

public sealed class CommandPackException : Exception
{
    public CommandPackException(string message)
        : base(message)
    {
    }

    public CommandPackException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
