using System;
using System.Threading;

namespace AssessmentTool.Windows.Components;

public enum ComponentFailure
{
    None,
    Missing,
    InvalidTrustedPath,
    UnsafeFileIdentity,
    HashMismatch,
    InvalidHash,
    VersionTooLow,
    InvalidVersion,
    ArchitectureMismatch,
    FileChangedDuringInspection,
    InspectionFailed
}

public sealed class ComponentFileIdentity
{
    private readonly string canonicalAbsolutePath;

    internal ComponentFileIdentity(
        string canonicalAbsolutePath,
        string sha256,
        long length,
        DateTime lastWriteTimeUtc,
        uint volumeSerialNumber,
        ulong fileIndex,
        uint linkCount)
    {
        this.canonicalAbsolutePath = RequiredText(canonicalAbsolutePath, nameof(canonicalAbsolutePath));
        if (!ComponentDefinition.IsSha256(sha256))
        {
            throw new ArgumentException("组件身份 SHA-256 无效。", nameof(sha256));
        }

        if (length < 0 || linkCount != 1)
        {
            throw new ArgumentException("组件文件身份无效。", nameof(length));
        }

        Sha256 = sha256.ToLowerInvariant();
        Length = length;
        LastWriteTimeUtc = lastWriteTimeUtc.ToUniversalTime();
        VolumeSerialNumber = volumeSerialNumber;
        FileIndex = fileIndex;
        LinkCount = linkCount;
    }

    public string Sha256 { get; }
    public long Length { get; }
    public DateTime LastWriteTimeUtc { get; }
    public uint VolumeSerialNumber { get; }
    public ulong FileIndex { get; }
    public uint LinkCount { get; }

    internal bool Matches(ComponentFileIdentity other)
    {
        return other != null
            && string.Equals(canonicalAbsolutePath, other.canonicalAbsolutePath, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Sha256, other.Sha256, StringComparison.OrdinalIgnoreCase)
            && Length == other.Length
            && LastWriteTimeUtc.Equals(other.LastWriteTimeUtc)
            && VolumeSerialNumber == other.VolumeSerialNumber
            && FileIndex == other.FileIndex
            && LinkCount == other.LinkCount;
    }

    private static string RequiredText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("组件身份字段不能为空。", parameterName);
        }

        return value;
    }
}

public sealed class ComponentStatus
{
    internal ComponentStatus(
        bool available,
        ComponentFailure failure,
        string componentId,
        string affectedFeature,
        string userImpact,
        string offlineInstructions,
        ComponentFileIdentity? verifiedIdentity,
        string definitionKey)
    {
        if (available != (failure == ComponentFailure.None) || available != (verifiedIdentity != null))
        {
            throw new ArgumentException("组件可用状态与验证身份不一致。", nameof(available));
        }

        Available = available;
        Failure = failure;
        ComponentId = RequiredText(componentId, nameof(componentId));
        AffectedFeature = RequiredText(affectedFeature, nameof(affectedFeature));
        UserImpact = RequiredText(userImpact, nameof(userImpact));
        OfflineInstructions = RequiredText(offlineInstructions, nameof(offlineInstructions));
        VerifiedIdentity = verifiedIdentity;
        DefinitionKey = RequiredText(definitionKey, nameof(definitionKey));
    }

    public bool Available { get; }
    public ComponentFailure Failure { get; }
    public string ComponentId { get; }
    public string AffectedFeature { get; }
    public string UserImpact { get; }
    public string OfflineInstructions { get; }
    public ComponentFileIdentity? VerifiedIdentity { get; }
    public bool RequiresUserConfirmationBeforeInstall => !Available;
    public bool AutomaticallyInstalls => false;
    internal string DefinitionKey { get; }

    private static string RequiredText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("组件状态字段不能为空。", parameterName);
        }

        return value;
    }
}

public sealed class ComponentExecutionCandidate : IDisposable
{
    private readonly object syncRoot = new object();
    private readonly IComponentFileHandle lease;
    private readonly string executablePath;
    private bool disposed;
    private bool inUse;
    private int launchThreadId;

    internal ComponentExecutionCandidate(
        string componentId,
        ComponentFileIdentity verifiedIdentity,
        string executablePath,
        IComponentFileHandle handle)
    {
        ComponentId = componentId ?? throw new ArgumentNullException(nameof(componentId));
        VerifiedIdentity = verifiedIdentity ?? throw new ArgumentNullException(nameof(verifiedIdentity));
        this.executablePath = string.IsNullOrWhiteSpace(executablePath)
            ? throw new ArgumentException("组件执行路径不能为空。", nameof(executablePath))
            : executablePath;
        lease = handle ?? throw new ArgumentNullException(nameof(handle));
    }

    public string ComponentId { get; }
    public ComponentFileIdentity VerifiedIdentity { get; }
    public bool WasRevalidatedForExecution
    {
        get
        {
            lock (syncRoot)
            {
                return !disposed;
            }
        }
    }

    internal void LaunchWhileLocked(Action<string> launch)
    {
        if (launch == null)
        {
            throw new ArgumentNullException(nameof(launch));
        }

        lock (syncRoot)
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(ComponentExecutionCandidate));
            }

            if (inUse)
            {
                throw new InvalidOperationException("组件执行候选当前正在使用。");
            }

            inUse = true;
            launchThreadId = Thread.CurrentThread.ManagedThreadId;
        }

        try
        {
            lease.ValidateLease();
            try
            {
                launch(executablePath);
            }
            finally
            {
                lease.ValidateLease();
            }
        }
        finally
        {
            lock (syncRoot)
            {
                inUse = false;
                launchThreadId = 0;
                Monitor.PulseAll(syncRoot);
            }
        }
    }

    public void Dispose()
    {
        lock (syncRoot)
        {
            if (inUse && launchThreadId == Thread.CurrentThread.ManagedThreadId)
            {
                throw new InvalidOperationException("启动回调执行期间不能重入释放组件租约。");
            }

            while (inUse)
            {
                Monitor.Wait(syncRoot);
            }

            if (!disposed)
            {
                disposed = true;
                lease.Dispose();
            }
        }
    }
}

public sealed class ComponentExecutionValidationException : Exception
{
    internal ComponentExecutionValidationException(string message)
        : base(message)
    {
    }
}
