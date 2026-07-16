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
