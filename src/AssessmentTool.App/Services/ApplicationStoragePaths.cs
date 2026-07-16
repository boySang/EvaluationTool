using System;
using System.Data.SQLite;
using System.IO;

namespace AssessmentTool.App.Services;

public sealed class ApplicationStoragePaths
{
    private ApplicationStoragePaths(
        string rootDirectory,
        string databasePath,
        string credentialRootDirectory,
        string sqliteConnectionString)
    {
        RootDirectory = rootDirectory;
        DatabasePath = databasePath;
        CredentialRootDirectory = credentialRootDirectory;
        SqliteConnectionString = sqliteConnectionString;
    }

    public string RootDirectory { get; }
    public string DatabasePath { get; }
    public string CredentialRootDirectory { get; }
    public string SqliteConnectionString { get; }

    public static ApplicationStoragePaths ForCurrentUser()
    {
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localApplicationData))
        {
            throw new InvalidOperationException("无法确定当前 Windows 用户的本地应用数据目录。");
        }

        return Create(Path.Combine(localApplicationData, "EvaluationTool"));
    }

    public static ApplicationStoragePaths Create(string? trustedUserRoot)
    {
        if (string.IsNullOrWhiteSpace(trustedUserRoot))
        {
            throw new ArgumentException("本地数据根目录不能为空。", nameof(trustedUserRoot));
        }

        var rootDirectory = Path.GetFullPath(trustedUserRoot);
        var dataDirectory = Path.Combine(rootDirectory, "data");
        var credentialRootDirectory = Path.Combine(rootDirectory, "security");
        Directory.CreateDirectory(rootDirectory);
        Directory.CreateDirectory(dataDirectory);
        Directory.CreateDirectory(credentialRootDirectory);

        var databasePath = Path.Combine(dataDirectory, "assessment.db");
        var connection = new SQLiteConnectionStringBuilder
        {
            DataSource = databasePath,
            Version = 3,
            DefaultTimeout = 5,
            JournalMode = SQLiteJournalModeEnum.Wal,
            Pooling = false
        };

        return new ApplicationStoragePaths(
            rootDirectory,
            databasePath,
            credentialRootDirectory,
            connection.ConnectionString);
    }
}
