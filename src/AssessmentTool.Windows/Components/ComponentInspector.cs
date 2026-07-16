using System;
using System.IO;

namespace AssessmentTool.Windows.Components;

public sealed class ComponentInspector
{
    private readonly string trustedApplicationRoot;
    private readonly IComponentFileSystem fileSystem;
    private readonly IComponentVersionReader versionReader;
    private readonly IComponentArchitectureReader architectureReader;
    private readonly IComponentHashReader hashReader;

    public ComponentInspector()
        : this(AppDomain.CurrentDomain.BaseDirectory)
    {
    }

    public ComponentInspector(string trustedApplicationRoot)
        : this(
            trustedApplicationRoot,
            new PhysicalComponentFileSystem(),
            new PhysicalComponentVersionReader(),
            new PeComponentArchitectureReader(),
            new Sha256ComponentHashReader())
    {
    }

    internal ComponentInspector(
        string trustedApplicationRoot,
        IComponentFileSystem fileSystem,
        IComponentVersionReader versionReader,
        IComponentArchitectureReader architectureReader,
        IComponentHashReader hashReader)
    {
        if (string.IsNullOrWhiteSpace(trustedApplicationRoot))
        {
            throw new ArgumentException("程序受信根目录不能为空。", nameof(trustedApplicationRoot));
        }

        this.fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        this.versionReader = versionReader ?? throw new ArgumentNullException(nameof(versionReader));
        this.architectureReader = architectureReader ?? throw new ArgumentNullException(nameof(architectureReader));
        this.hashReader = hashReader ?? throw new ArgumentNullException(nameof(hashReader));
        this.trustedApplicationRoot = fileSystem.ValidateTrustedRoot(trustedApplicationRoot);
    }

    public ComponentStatus Inspect(ComponentDefinition definition)
    {
        if (definition == null)
        {
            throw new ArgumentNullException(nameof(definition));
        }

        string absolutePath;
        try
        {
            absolutePath = fileSystem.ResolveTrustedPath(trustedApplicationRoot, definition.TrustedRelativePath);
        }
        catch (Exception)
        {
            return Unavailable(definition, ComponentFailure.InvalidTrustedPath, "组件固定路径无法安全解析，已拒绝检测。");
        }

        try
        {
            if (!fileSystem.FileExists(absolutePath))
            {
                return Unavailable(definition, ComponentFailure.Missing, "未找到所需的离线组件。");
            }

            using (var handle = fileSystem.OpenRead(trustedApplicationRoot, absolutePath))
            {
                return InspectOpenedHandle(definition, absolutePath, handle);
            }
        }
        catch (InvalidDataException)
        {
            return Unavailable(definition, ComponentFailure.UnsafeFileIdentity, "组件文件或父目录身份不安全，已拒绝使用。");
        }
        catch (Exception)
        {
            return Unavailable(definition, ComponentFailure.InspectionFailed, "组件检查失败，已拒绝使用该组件。");
        }
    }

    public ComponentExecutionCandidate RevalidateForExecution(
        ComponentDefinition definition,
        ComponentStatus inspectedStatus)
    {
        if (definition == null)
        {
            throw new ArgumentNullException(nameof(definition));
        }

        if (inspectedStatus == null)
        {
            throw new ArgumentNullException(nameof(inspectedStatus));
        }

        if (!inspectedStatus.Available
            || inspectedStatus.VerifiedIdentity == null
            || !string.Equals(inspectedStatus.ComponentId, definition.Id, StringComparison.Ordinal)
            || !string.Equals(inspectedStatus.DefinitionKey, definition.DefinitionKey, StringComparison.Ordinal))
        {
            throw new ComponentExecutionValidationException("组件尚未形成可重新验证的执行候选。");
        }

        IComponentFileHandle? handle = null;
        try
        {
            var absolutePath = fileSystem.ResolveTrustedPath(trustedApplicationRoot, definition.TrustedRelativePath);
            if (!fileSystem.FileExists(absolutePath))
            {
                throw new ComponentExecutionValidationException("组件执行前重新验证失败，文件可能已被替换或修改。");
            }

            handle = fileSystem.OpenRead(trustedApplicationRoot, absolutePath);
            var currentStatus = InspectOpenedHandle(definition, absolutePath, handle);
            if (!currentStatus.Available
                || currentStatus.VerifiedIdentity == null
                || !inspectedStatus.VerifiedIdentity.Matches(currentStatus.VerifiedIdentity))
            {
                throw new ComponentExecutionValidationException("组件执行前重新验证失败，文件可能已被替换或修改。");
            }

            var candidate = new ComponentExecutionCandidate(
                definition.Id,
                currentStatus.VerifiedIdentity,
                absolutePath,
                handle);
            handle = null;
            return candidate;
        }
        catch (ComponentExecutionValidationException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new ComponentExecutionValidationException("组件执行前重新验证失败，文件可能已被替换或修改。");
        }
        finally
        {
            handle?.Dispose();
        }
    }

    private ComponentStatus InspectOpenedHandle(
        ComponentDefinition definition,
        string absolutePath,
        IComponentFileHandle handle)
    {
        handle.ValidateLease();
        var before = handle.CaptureSnapshot();
        if (before.IsReparsePoint
            || before.LinkCount != 1
            || !string.Equals(before.CanonicalAbsolutePath, absolutePath, StringComparison.OrdinalIgnoreCase))
        {
            return Unavailable(definition, ComponentFailure.UnsafeFileIdentity, "组件文件路径或链接身份不安全。");
        }

        if (!handle.Stream.CanRead || !handle.Stream.CanSeek)
        {
            return Unavailable(definition, ComponentFailure.InspectionFailed, "组件文件无法从受控句柄读取，已拒绝使用。");
        }

        var actualHash = hashReader.ComputeSha256(handle.Stream);
        handle.Stream.Position = 0;
        var actualArchitecture = architectureReader.ReadArchitecture(handle.Stream);
        var actualVersion = versionReader.GetFileVersion(handle, absolutePath);
        handle.ValidateLease();
        var after = handle.CaptureSnapshot();
        if (!before.Equals(after))
        {
            return Unavailable(definition, ComponentFailure.FileChangedDuringInspection, "组件在校验期间发生变化，已拒绝使用。");
        }

        if (!ComponentDefinition.IsSha256(actualHash))
        {
            return Unavailable(definition, ComponentFailure.InvalidHash, "组件哈希格式无效，已拒绝使用。");
        }

        if (!string.Equals(definition.ExpectedSha256, actualHash, StringComparison.OrdinalIgnoreCase))
        {
            return Unavailable(definition, ComponentFailure.HashMismatch, "组件完整性校验失败，已拒绝使用。");
        }

        if (!ComponentDefinition.TryParseStrictVersion(actualVersion, out var parsedVersion))
        {
            return Unavailable(definition, ComponentFailure.InvalidVersion, "组件文件版本格式无效，已拒绝使用。");
        }

        ComponentDefinition.TryParseStrictVersion(definition.MinimumVersion, out var minimumVersion);
        if (parsedVersion.CompareTo(minimumVersion) < 0)
        {
            return Unavailable(definition, ComponentFailure.VersionTooLow, "组件版本低于受信任要求，已拒绝使用。");
        }

        if (actualArchitecture != definition.RequiredArchitecture)
        {
            return Unavailable(definition, ComponentFailure.ArchitectureMismatch, "组件架构与定义要求不匹配，已拒绝使用。");
        }

        var identity = new ComponentFileIdentity(
            before.CanonicalAbsolutePath,
            actualHash,
            before.Length,
            before.LastWriteTimeUtc,
            before.VolumeSerialNumber,
            before.FileIndex,
            before.LinkCount);
        return new ComponentStatus(
            available: true,
            failure: ComponentFailure.None,
            definition.Id,
            definition.AffectedFeature,
            definition.AffectedFeature + "组件已通过诊断检查；它仍是候选，执行前必须重新验证文件身份和哈希。",
            "组件已通过固定路径、SHA-256、版本、架构和文件身份检查；本工具不会自动安装组件。",
            identity,
            definition.DefinitionKey);
    }

    private static ComponentStatus Unavailable(ComponentDefinition definition, ComponentFailure failure, string reason)
    {
        return new ComponentStatus(
            available: false,
            failure,
            definition.Id,
            definition.AffectedFeature,
            definition.AffectedFeature + "暂不可用：" + reason + "其他不依赖该组件的功能仍可继续使用。",
            "请从软件旁的“依赖组件”目录选择经许可证审查且 SHA-256 已核验的离线组件，完成后重新检测。安装前需要您确认；本工具不会自动安装。原因：" + reason,
            verifiedIdentity: null,
            definition.DefinitionKey);
    }
}
