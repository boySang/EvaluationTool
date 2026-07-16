using System;
using System.Collections.Generic;
using System.IO;

namespace AssessmentTool.Windows.Storage;

internal static class MigrationSequence
{
    public static void Validate(IReadOnlyList<int> versions)
    {
        if (versions == null)
        {
            throw new ArgumentNullException(nameof(versions));
        }

        if (versions.Count == 0)
        {
            throw new InvalidDataException("At least one built-in SQLite migration is required.");
        }

        var seenVersions = new HashSet<int>();
        for (var index = 0; index < versions.Count; index++)
        {
            var version = versions[index];
            var expectedVersion = index + 1;
            if (version != expectedVersion || !seenVersions.Add(version))
            {
                throw new InvalidDataException("Built-in SQLite migrations must be unique and contiguous from version 1.");
            }
        }
    }
}
