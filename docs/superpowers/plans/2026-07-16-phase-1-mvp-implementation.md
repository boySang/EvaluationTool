# Phase 1 MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a lightweight Windows MVP that creates projects and devices, connects through SSH, identifies a supported target, executes only verified read-only commands, and saves raw output plus screenshot evidence.

**Architecture:** Keep all command policy, detection, task state, and evidence naming rules in a `netstandard2.0` core so they can be tested independently of Windows. Put WPF, DPAPI, SQLite, Plink process control, PNG rendering, and dependency checks behind interfaces in Windows-only projects targeting .NET Framework 4.8. The first release supports a single-device SSH workflow; Telnet, serial, databases, middleware, batch import, and broad vendor packs are separate follow-up plans.

**Tech Stack:** C#; WPF; .NET Framework 4.8; .NET Standard 2.0; SDK-style projects; xUnit 2; SQLite via `System.Data.SQLite.Core`; JSON via `Newtonsoft.Json`; PuTTY/Plink; Windows DPAPI; Inno Setup; native Win32 bootstrapper.

## Global Constraints

- Official runtime targets are Windows 10 and Windows 11.
- Core portable package target is 20–40 MB; installer target is 30–60 MB, measured after publishing.
- All automatic remote commands are verified read-only commands; no setting can disable this policy.
- Automatic collection has no arbitrary command text box.
- Unknown or low-confidence target identification stops before the full command pack runs.
- No broad port scan, vulnerability scan, or discovery outside the exact host and connection supplied by the user.
- Passwords, private-key passphrases, and sensitive connection strings never appear in logs or process arguments.
- Missing optional components disable only their feature and show a Chinese remediation path.
- The app remains useful offline; network downloads are optional and require confirmation.
- Do not create Git commits unless the user explicitly requests them; use task review checkpoints instead.

---

## Planned File Structure

```text
AssessmentTool.sln
Directory.Build.props
src/
  AssessmentTool.Core/
    AssessmentTool.Core.csproj
    Domain/ConnectionProfile.cs
    Domain/CommandDefinition.cs
    Domain/DetectionResult.cs
    Domain/ExecutionRecord.cs
    Security/CommandSafetyPolicy.cs
    Detection/DetectionEngine.cs
    Detection/HostDatabaseDiscovery.cs
    Execution/CollectionRunner.cs
    Evidence/EvidencePathBuilder.cs
  AssessmentTool.Windows/
    AssessmentTool.Windows.csproj
    Credentials/DpapiCredentialVault.cs
    Components/ComponentInspector.cs
    Components/ComponentStatus.cs
    Processes/IProcessRunner.cs
    Processes/WindowsProcessRunner.cs
    Sessions/PlinkArgumentsBuilder.cs
    Sessions/PlinkSession.cs
    Storage/SqliteProjectRepository.cs
    Evidence/WpfEvidenceRenderer.cs
  AssessmentTool.App/
    AssessmentTool.App.csproj
    App.xaml
    App.xaml.cs
    MainWindow.xaml
    MainWindow.xaml.cs
    ViewModels/MainViewModel.cs
    ViewModels/DeviceEditorViewModel.cs
    ViewModels/CollectionViewModel.cs
    Themes/Colors.xaml
    Themes/Controls.xaml
  AssessmentTool.Bootstrapper/
    AssessmentTool.Bootstrapper.vcxproj
    main.cpp
tests/
  AssessmentTool.Core.Tests/
    AssessmentTool.Core.Tests.csproj
    Security/CommandSafetyPolicyTests.cs
    Detection/DetectionEngineTests.cs
    Execution/CollectionRunnerTests.cs
    Evidence/EvidencePathBuilderTests.cs
  AssessmentTool.Windows.Tests/
    AssessmentTool.Windows.Tests.csproj
    Sessions/PlinkArgumentsBuilderTests.cs
    Components/ComponentInspectorTests.cs
    Storage/SqliteProjectRepositoryTests.cs
    Evidence/WpfEvidenceRendererTests.cs
command-packs/
  schema/command-pack.schema.json
  builtin/generic-linux.json
  builtin/database-host-discovery-linux.json
  builtin/test-network-device.json
installer/AssessmentTool.iss
build/Measure-Package.ps1
```

## Task 1: Create the solution and core domain contracts

**Files:**
- Create: `AssessmentTool.sln`
- Create: `Directory.Build.props`
- Create: `src/AssessmentTool.Core/AssessmentTool.Core.csproj`
- Create: `src/AssessmentTool.Core/Domain/ConnectionProfile.cs`
- Create: `src/AssessmentTool.Core/Domain/CommandDefinition.cs`
- Create: `src/AssessmentTool.Core/Domain/DetectionResult.cs`
- Create: `src/AssessmentTool.Core/Domain/ExecutionRecord.cs`
- Create: `tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj`
- Create: `tests/AssessmentTool.Core.Tests/Domain/DomainContractTests.cs`

**Interfaces:**
- Produces: `ConnectionProfile`, `CommandDefinition`, `DetectionCandidate`, `DetectionResult`, `ExecutionRecord`, and enums used by all later tasks.
- Consumes: none.

- [ ] **Step 1: Add the solution-wide build settings**

```xml
<Project>
  <PropertyGroup>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
  </PropertyGroup>
</Project>
```

- [ ] **Step 2: Add the core and test projects**

```xml
<!-- src/AssessmentTool.Core/AssessmentTool.Core.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
  </PropertyGroup>
</Project>
```

```xml
<!-- tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.11.1" />
    <PackageReference Include="xunit" Version="2.9.2" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.8.2" PrivateAssets="all" />
    <ProjectReference Include="../../src/AssessmentTool.Core/AssessmentTool.Core.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 3: Write a failing domain contract test**

```csharp
[Fact]
public void ConnectionProfile_defaults_to_automatic_detection()
{
    var profile = new ConnectionProfile("交换机A", "192.0.2.10", 22, ConnectionProtocol.Ssh);

    Assert.Equal(TargetCategory.Automatic, profile.TargetCategory);
    Assert.Equal("交换机A", profile.DisplayName);
}
```

- [ ] **Step 4: Run the domain test and verify it fails**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter ConnectionProfile_defaults_to_automatic_detection`

Expected: FAIL because `ConnectionProfile` does not exist.

- [ ] **Step 5: Implement the domain contracts**

```csharp
public enum ConnectionProtocol { Ssh, Telnet, Serial, WinRm }
public enum TargetCategory { Automatic, NetworkDevice, Server, Database, Middleware, SecurityDevice }
public enum VerificationStatus { Pending, Verified, Rejected }
public enum ExecutionStatus { Pending, Running, Succeeded, Failed, Skipped, Stopped }

public sealed class ConnectionProfile
{
    public ConnectionProfile(string displayName, string host, int port, ConnectionProtocol protocol)
    {
        DisplayName = displayName ?? throw new ArgumentNullException(nameof(displayName));
        Host = host ?? throw new ArgumentNullException(nameof(host));
        Port = port;
        Protocol = protocol;
        TargetCategory = TargetCategory.Automatic;
    }

    public string DisplayName { get; }
    public string Host { get; }
    public int Port { get; }
    public ConnectionProtocol Protocol { get; }
    public TargetCategory TargetCategory { get; set; }
    public SshEndpointIdentity? SshEndpoint { get; }
    public SshConnectionOptions? SshOptions { get; }
}
```

Define `CommandDefinition` with `Id`, `Title`, `TargetCategory`, `CommandText`, `VerificationStatus`, `IsReadOnly`, `Vendor`, `ProductFamily`, `MinimumVersion`, and `MaximumVersion`. Define `DetectionCandidate` with category/vendor/product/version/evidence/confidence. Define `DetectionResult` as an immutable candidate list plus `RequiresUserConfirmation`. Define `ExecutionRecord` with command id, exact command, timestamps, status, raw output path, evidence image paths, and error text.

- [ ] **Step 6: Run all core tests**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj`

Expected: PASS.

## Task 2: Enforce the permanent read-only command policy

**Files:**
- Create: `src/AssessmentTool.Core/Security/CommandSafetyPolicy.cs`
- Create: `tests/AssessmentTool.Core.Tests/Security/CommandSafetyPolicyTests.cs`

**Interfaces:**
- Consumes: `CommandDefinition` from Task 1.
- Produces: `CommandSafetyPolicy.Validate(CommandDefinition): SafetyDecision` and `SafetyDecision` with `Allowed`, `Code`, and `Message`.

- [ ] **Step 1: Write parameterized rejection tests**

```csharp
[Theory]
[InlineData("rm -rf /tmp/x")]
[InlineData("echo x > /etc/example")]
[InlineData("systemctl restart sshd")]
[InlineData("configure terminal")]
[InlineData("delete startup-config")]
[InlineData("UPDATE users SET enabled = 0")]
[InlineData("SELECT pg_write_file('/tmp/x', 'x')")]
[InlineData("docker restart db")]
public void Rejects_commands_with_side_effects(string commandText)
{
    var command = VerifiedReadOnlyCommand(commandText);

    var result = new CommandSafetyPolicy().Validate(command);

    Assert.False(result.Allowed);
    Assert.Equal("unsafe-command", result.Code);
}

[Fact]
public void Rejects_unverified_command_even_when_text_looks_safe()
{
    var command = new CommandDefinition("id", "版本", TargetCategory.Server, "uname -a")
    {
        VerificationStatus = VerificationStatus.Pending,
        IsReadOnly = true
    };

    Assert.False(new CommandSafetyPolicy().Validate(command).Allowed);
}
```

- [ ] **Step 2: Run the safety tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter CommandSafetyPolicyTests`

Expected: FAIL because `CommandSafetyPolicy` does not exist.

- [ ] **Step 3: Implement whitelist-first validation**

```csharp
public sealed class CommandSafetyPolicy
{
    private static readonly Regex ForbiddenSyntax = new Regex(
        @"(;|&&|\|\||>|>>|<|`|\$\(|\b(rm|mv|cp|tee|sed\s+-i|systemctl\s+(start|stop|restart)|service\s+\S+\s+(start|stop|restart)|configure|delete|write\s+memory|reload|shutdown|reboot|docker\s+(run|start|stop|restart|rm)|podman\s+(run|start|stop|restart|rm)|insert|update|delete|merge|create|alter|drop|truncate|grant|revoke|execute|exec|copy\s+.*\s+to)\b)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public SafetyDecision Validate(CommandDefinition command)
    {
        if (command.VerificationStatus != VerificationStatus.Verified || !command.IsReadOnly)
            return SafetyDecision.Reject("unverified-command", "命令尚未通过只读校验");

        if (string.IsNullOrWhiteSpace(command.CommandText) || ForbiddenSyntax.IsMatch(command.CommandText))
            return SafetyDecision.Reject("unsafe-command", "命令包含可能修改目标的操作");

        return SafetyDecision.Allow();
    }
}
```

Keep this regex as a second barrier, not as the source of trust: only verified command-pack entries can reach it. Add tests proving `show version`, `display version`, `uname -a`, `Get-ComputerInfo`, and a vendor-approved database metadata query pass.

- [ ] **Step 4: Run all safety tests**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter CommandSafetyPolicyTests`

Expected: PASS.

## Task 3: Define and load versioned command packs

**Files:**
- Create: `command-packs/schema/command-pack.schema.json`
- Create: `command-packs/builtin/generic-linux.json`
- Create: `command-packs/builtin/test-network-device.json`
- Create: `src/AssessmentTool.Core/Commands/CommandPack.cs`
- Create: `src/AssessmentTool.Core/Commands/CommandPackLoader.cs`
- Create: `src/AssessmentTool.Core/Commands/CommandMatcher.cs`
- Create: `tests/AssessmentTool.Core.Tests/Commands/CommandPackTests.cs`
- Modify: `src/AssessmentTool.Core/AssessmentTool.Core.csproj`

**Interfaces:**
- Consumes: `CommandDefinition` and `CommandSafetyPolicy`.
- Produces: `CommandPackLoader.Load(string json): CommandPack` and `CommandMatcher.Match(CommandPack, DetectionCandidate): IReadOnlyList<CommandDefinition>`.

- [ ] **Step 1: Add JSON support**

```xml
<ItemGroup>
  <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
</ItemGroup>
```

- [ ] **Step 2: Write failing pack validation tests**

```csharp
[Fact]
public void Loader_rejects_a_pack_with_an_unverified_command()
{
    var json = PackJson(command: "uname -a", verificationStatus: "Pending");

    var error = Assert.Throws<CommandPackException>(() => new CommandPackLoader().Load(json));

    Assert.Contains("正式命令包只能包含已验证命令", error.Message);
}

[Fact]
public void Matcher_prefers_exact_vendor_family_and_version()
{
    var pack = new CommandPackLoader().Load(ExactAndGenericPackJson());
    var target = new DetectionCandidate(TargetCategory.NetworkDevice, "VendorA", "FamilyX", "7.2", "fixture", 0.98m);

    var commands = new CommandMatcher().Match(pack, target);

    Assert.Equal("vendor-a-family-x-7-version", commands[0].Id);
}
```

- [ ] **Step 3: Run the tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter CommandPackTests`

Expected: FAIL because pack types do not exist.

- [ ] **Step 4: Implement strict loading and deterministic matching**

`CommandPackLoader` must reject duplicate ids, empty sources, missing version, pending commands, non-read-only commands, and any command rejected by `CommandSafetyPolicy`. `CommandMatcher` must score exact vendor + family + version above family-only, vendor-only, and category-generic matches; preserve pack order within equal scores; and return no commands when the candidate requires confirmation.

```csharp
public IReadOnlyList<CommandDefinition> Match(CommandPack pack, DetectionCandidate target)
{
    return pack.Commands
        .Where(command => command.TargetCategory == target.Category)
        .Select(command => new { Command = command, Score = Score(command, target) })
        .Where(item => item.Score >= 0)
        .OrderByDescending(item => item.Score)
        .ThenBy(item => item.Command.Id, StringComparer.Ordinal)
        .Select(item => item.Command)
        .ToArray();
}
```

- [ ] **Step 5: Add minimal built-in packs**

`generic-linux.json` contains only verified identification and collection commands such as `uname -a`, `cat /etc/os-release`, and `hostname`. `test-network-device.json` contains fixture-only `show version` and `show clock`; label the vendor `AssessmentTool.TestFixture` so it cannot be mistaken for production vendor support.

- [ ] **Step 6: Run command-pack tests**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter CommandPackTests`

Expected: PASS.

## Task 4: Add automatic identification with manual fallback

**Files:**
- Create: `src/AssessmentTool.Core/Detection/IdentificationRule.cs`
- Create: `src/AssessmentTool.Core/Detection/DetectionEngine.cs`
- Create: `tests/AssessmentTool.Core.Tests/Detection/DetectionEngineTests.cs`

**Interfaces:**
- Consumes: transcript text and fixed `IdentificationRule` instances from verified command packs.
- Produces: `DetectionEngine.Detect(string transcript, IReadOnlyList<IdentificationRule>): DetectionResult`.

- [ ] **Step 1: Write confidence and ambiguity tests**

```csharp
[Fact]
public void Unique_high_confidence_match_is_accepted_automatically()
{
    var result = Engine().Detect("VendorA Network OS 7.2 Model X100", Rules());

    Assert.False(result.RequiresUserConfirmation);
    Assert.Equal("VendorA", result.Candidates.Single().Vendor);
}

[Fact]
public void Conflicting_matches_require_user_confirmation()
{
    var result = Engine().Detect("VendorA compatible VendorB shell", Rules());

    Assert.True(result.RequiresUserConfirmation);
    Assert.True(result.Candidates.Count >= 2);
}

[Fact]
public void Unknown_output_does_not_guess()
{
    var result = Engine().Detect("unknown appliance", Rules());

    Assert.True(result.RequiresUserConfirmation);
    Assert.Empty(result.Candidates);
}
```

- [ ] **Step 2: Run detection tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter DetectionEngineTests`

Expected: FAIL because the engine does not exist.

- [ ] **Step 3: Implement evidence-based scoring**

```csharp
public DetectionResult Detect(string transcript, IReadOnlyList<IdentificationRule> rules)
{
    var candidates = rules
        .Select(rule => rule.TryMatch(transcript))
        .Where(candidate => candidate != null)
        .Cast<DetectionCandidate>()
        .OrderByDescending(candidate => candidate.Confidence)
        .ToArray();

    var uniqueHigh = candidates.Length == 1 && candidates[0].Confidence >= 0.90m;
    return new DetectionResult(candidates, requiresUserConfirmation: !uniqueHigh);
}
```

Rules use anchored, vendor-specific regex patterns and must store the exact matched evidence. Do not infer a version when no version capture matched.

- [ ] **Step 4: Run detection tests**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter DetectionEngineTests`

Expected: PASS.

## Task 5: Persist projects, devices, and evidence indexes in SQLite

**Files:**
- Create: `src/AssessmentTool.Windows/AssessmentTool.Windows.csproj`
- Create: `src/AssessmentTool.Windows/Storage/IProjectRepository.cs`
- Create: `src/AssessmentTool.Windows/Storage/SqliteProjectRepository.cs`
- Create: `src/AssessmentTool.Windows/Storage/Migrations/001_initial.sql`
- Create: `tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj`
- Create: `tests/AssessmentTool.Windows.Tests/Storage/SqliteProjectRepositoryTests.cs`

**Interfaces:**
- Consumes: core domain ids and records.
- Produces: `IProjectRepository.InitializeAsync`, `CreateProjectAsync`, `AddDeviceAsync`, `SaveExecutionAsync`, and read methods returning immutable DTOs.

- [ ] **Step 1: Add the Windows infrastructure project**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net48</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="System.Data.SQLite.Core" Version="1.0.119" />
    <ProjectReference Include="../AssessmentTool.Core/AssessmentTool.Core.csproj" />
  </ItemGroup>
</Project>
```

The Windows test project targets `net48`, references xUnit and `AssessmentTool.Windows`, and runs only on Windows.

- [ ] **Step 2: Write a failing persistence round-trip test**

```csharp
[Fact]
public async Task Project_and_device_round_trip_without_storing_plaintext_secret()
{
    using var database = TemporaryDatabase.Create();
    var repository = new SqliteProjectRepository(database.ConnectionString);
    await repository.InitializeAsync();

    var projectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
    await repository.AddDeviceAsync(projectId, "交换机A", "192.0.2.10", 22, "credential-1");

    var device = Assert.Single(await repository.GetDevicesAsync(projectId));
    Assert.Equal("credential-1", device.CredentialReference);
    Assert.DoesNotContain("password", File.ReadAllText(database.Path), StringComparison.OrdinalIgnoreCase);
}
```

- [ ] **Step 3: Run the Windows storage test and verify it fails**

Run in Windows Developer PowerShell: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter SqliteProjectRepositoryTests`

Expected: FAIL because the repository does not exist.

- [ ] **Step 4: Implement schema migration and parameterized SQL**

Create tables `schema_version`, `projects`, `devices`, `executions`, and `evidence_files`. Store only a credential reference in `devices`. Every SQL statement uses `SQLiteParameter`; enable foreign keys with `PRAGMA foreign_keys = ON`; wrap each write operation in a transaction.

```csharp
using (var command = connection.CreateCommand())
{
    command.CommandText = "INSERT INTO projects(id, customer_name, project_name, evidence_root) VALUES(@id,@customer,@project,@root)";
    command.Parameters.AddWithValue("@id", id.ToString("D"));
    command.Parameters.AddWithValue("@customer", customerName);
    command.Parameters.AddWithValue("@project", projectName);
    command.Parameters.AddWithValue("@root", evidenceRoot);
    await command.ExecuteNonQueryAsync().ConfigureAwait(false);
}
```

- [ ] **Step 5: Run storage tests**

Run: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter SqliteProjectRepositoryTests`

Expected: PASS.

## Task 6: Protect credentials and inspect required components

**Files:**
- Create: `src/AssessmentTool.Windows/Credentials/ICredentialVault.cs`
- Create: `src/AssessmentTool.Windows/Credentials/DpapiCredentialVault.cs`
- Create: `src/AssessmentTool.Windows/Components/ComponentStatus.cs`
- Create: `src/AssessmentTool.Windows/Components/ComponentInspector.cs`
- Create: `tests/AssessmentTool.Windows.Tests/Credentials/DpapiCredentialVaultTests.cs`
- Create: `tests/AssessmentTool.Windows.Tests/Components/ComponentInspectorTests.cs`

**Interfaces:**
- Produces: `ICredentialVault.Store`, `Retrieve`, `Delete`; `ComponentInspector.Inspect(ComponentDefinition): ComponentStatus`.
- Consumes: Windows DPAPI, registry, filesystem, and exact bundled-tool hashes.

- [ ] **Step 1: Write credential round-trip and plaintext tests**

```csharp
[Fact]
public void Stored_secret_is_encrypted_and_round_trips_for_current_user()
{
    using var folder = TemporaryFolder.Create();
    var vault = new DpapiCredentialVault(folder.Path);

    vault.Store("credential-1", "S3cret!");

    Assert.Equal("S3cret!", vault.Retrieve("credential-1"));
    Assert.DoesNotContain("S3cret!", File.ReadAllText(Path.Combine(folder.Path, "credential-1.bin")));
}
```

- [ ] **Step 2: Write missing-component remediation tests**

```csharp
[Fact]
public void Missing_plink_reports_impact_and_offline_remediation()
{
    var inspector = new ComponentInspector(new FakeFileSystem(fileExists: false));

    var status = inspector.Inspect(ComponentDefinition.Plink(@"tools\plink.exe", expectedSha256: "ABC"));

    Assert.False(status.Available);
    Assert.Equal("SSH连接", status.AffectedFeature);
    Assert.Contains("依赖组件", status.OfflineInstructions);
    Assert.True(status.RequiresUserConfirmationBeforeInstall);
}
```

- [ ] **Step 3: Run tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter "DpapiCredentialVaultTests|ComponentInspectorTests"`

Expected: FAIL because vault and inspector do not exist.

- [ ] **Step 4: Implement DPAPI and component status**

Use `ProtectedData.Protect` and `ProtectedData.Unprotect` with `DataProtectionScope.CurrentUser` and 32 bytes of per-installation entropy stored in an ACL-restricted file. Write encrypted bytes atomically through a temporary file. `ComponentInspector` checks existence, version, SHA-256, and architecture; it returns data only and never installs automatically.

- [ ] **Step 5: Run credential and component tests**

Run: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter "DpapiCredentialVaultTests|ComponentInspectorTests"`

Expected: PASS.

## Task 7: Build safe Plink process execution

**Files:**
- Create: `src/AssessmentTool.Windows/Processes/IProcessRunner.cs`
- Create: `src/AssessmentTool.Windows/Processes/WindowsProcessRunner.cs`
- Create: `src/AssessmentTool.Windows/Sessions/PlinkArgumentsBuilder.cs`
- Create: `src/AssessmentTool.Windows/Sessions/PlinkSession.cs`
- Create: `tests/AssessmentTool.Windows.Tests/Sessions/PlinkArgumentsBuilderTests.cs`
- Create: `tests/AssessmentTool.Windows.Tests/Sessions/PlinkSessionTests.cs`

**Interfaces:**
- Consumes: `ConnectionProfile` with endpoint-bound immutable `SshOptions.HostKeyTrust`, credential material supplied through a protected temporary file, and an automatically executable `CommandDefinition`.
- Produces: `IRemoteSession.ExecuteAsync(CommandDefinition command, CancellationToken): CommandOutput`.

`HostKeyTrustState.Pinned` and `HostKeyTrustState.Verified` are both eligible for automatic connection. `Verified` means the same immutable endpoint and pinned fingerprint most recently passed Plink host-key verification; it does not replace or clear the pinned fingerprint. `Unconfigured`, `AwaitingProbe`, `AwaitingConfirmation`, and `MismatchBlocked` must all be rejected before process startup.

`HostKeyTrust` has no public constructor, public observation transition, public `AwaitingConfirmation` factory, or public `Confirm` transition. Windows production code obtains the sealed `HostKeyTrustCoordinator` from the public Core `HostKeyTrustServices.CreateCoordinator()` factory; only that coordinator can move `Unconfigured` through `AwaitingProbe`, record a validated endpoint-bound probe observation, create `AwaitingConfirmation`, and confirm it as `Pinned`. Callers cannot replace the coordinator with their own interface implementation or skip the probe state. Initial pins, matching verifications, mismatches, and every reconfirmation append immutable audit events containing endpoint, algorithm, fingerprint, UTC time, and source, so repeated key replacements never overwrite earlier history.

- [ ] **Step 1: Test that secrets never enter arguments**

```csharp
[Fact]
public void Password_profile_uses_pwfile_and_endpoint_bound_host_key_trust()
{
    var profile = ProfileWithHostKeyTrust(HostKeyTrustState.Pinned, "ssh-ed25519 255 SHA256:fixture");

    var arguments = new PlinkArgumentsBuilder().Build(profile, @"C:\secure\pw.txt");

    Assert.Contains("-batch", arguments);
    Assert.Contains("-hostkey", arguments);
    Assert.Contains("-pwfile", arguments);
    Assert.DoesNotContain("S3cret!", arguments);
}

[Fact]
public void Untrusted_host_key_state_blocks_batch_connection()
{
    Assert.Throws<HostKeyNotConfirmedException>(() =>
        new PlinkArgumentsBuilder().Build(ProfileWithHostKeyTrust(HostKeyTrustState.AwaitingConfirmation), @"C:\secure\pw.txt"));
}
```

- [ ] **Step 2: Run Plink argument tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter PlinkArgumentsBuilderTests`

Expected: FAIL because the builder does not exist.

- [ ] **Step 3: Implement exact argument tokens**

Build a token list rather than one interpolated shell string: `-ssh`, `-batch`, `-no-antispoof`, `-P`, port, `-l`, username, `-hostkey`, pinned fingerprint, and either `-i` key path or `-pwfile` protected temporary path. Validate host and port separately. Do not invoke `cmd.exe` or PowerShell.

- [ ] **Step 4: Test transcript capture, cancellation, and redaction**

Use a fake `IProcessRunner` that records executable and argument tokens and emits stdout/stderr chunks. Verify `PlinkSession` returns exact raw output, maps nonzero exit codes to a Chinese error category, kills the child process tree on cancellation, and redacts the temporary credential path from logs.

- [ ] **Step 5: Implement `WindowsProcessRunner` and `PlinkSession`**

`WindowsProcessRunner` uses `ProcessStartInfo.UseShellExecute = false`, redirects stdin/stdout/stderr, sets `CreateNoWindow = true`, reads both streams asynchronously, and never logs stdin. `PlinkSession` validates the command through `CommandSafetyPolicy` immediately before writing it to stdin.

- [ ] **Step 6: Run Plink session tests**

Run: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter "PlinkArgumentsBuilderTests|PlinkSessionTests"`

Expected: PASS.

## Task 8: Orchestrate identify, confirm, execute, and stop states

**Files:**
- Reuse: `src/AssessmentTool.Core/Domain/RemoteSessionContracts.cs`
- Modify: `src/AssessmentTool.Core/Domain/DetectionResult.cs`
- Create: `src/AssessmentTool.Core/Execution/CollectionRunner.cs`
- Create: `src/AssessmentTool.Core/Execution/CollectionProgress.cs`
- Create: `tests/AssessmentTool.Core.Tests/Execution/CollectionRunnerTests.cs`

**Interfaces:**
- Consumes: `IRemoteSession`, fixed identification commands, `DetectionEngine`, user-confirmed candidate, `CommandMatcher`, and `CommandSafetyPolicy`.
- Produces: `CollectionRunner.RunAsync(CollectionRequest, IProgress<CollectionProgress>, CancellationToken): CollectionResult`.

- [x] **Step 1: Write the safety-critical orchestration tests**

```csharp
[Fact]
public async Task Low_confidence_detection_stops_before_collection_commands()
{
    var session = new FakeSession("unknown appliance");
    var result = await Runner(session).RunAsync(Request(), Progress(), CancellationToken.None);

    Assert.Equal(CollectionOutcome.NeedsUserConfirmation, result.Outcome);
    Assert.DoesNotContain(session.Commands, command => command.Id.StartsWith("collect-"));
}

[Fact]
public async Task Unsafe_command_is_rejected_before_session_receives_it()
{
    var session = new FakeSession("VendorA Network OS 7.2 Model X100");
    var request = RequestWithCommand("configure terminal");

    var result = await Runner(session).RunAsync(request, Progress(), CancellationToken.None);

    Assert.Equal(CollectionOutcome.CommandRejected, result.Outcome);
    Assert.DoesNotContain("configure terminal", session.CommandTexts);
}
```

- [x] **Step 2: Run orchestration tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter CollectionRunnerTests`

Expected: FAIL because `CollectionRunner` does not exist.

- [x] **Step 3: Implement the explicit state machine**

States are `Connecting`, `Identifying`, `AwaitingConfirmation`, `PreparingCommands`, `Executing`, `SavingEvidence`, `Completed`, `Failed`, and `Stopped`. Identification commands are a separate fixed verified list. The runner revalidates every command immediately before `IRemoteSession.ExecuteAsync`. Cancellation stops before the next command and preserves completed outputs.

```csharp
foreach (var command in commands)
{
    cancellationToken.ThrowIfCancellationRequested();
    var decision = safetyPolicy.Validate(command);
    if (!decision.Allowed)
        return CollectionResult.CommandRejected(command.Id, decision.Message);

    progress.Report(CollectionProgress.Executing(command.Id));
    outputs.Add(await session.ExecuteAsync(command, cancellationToken).ConfigureAwait(false));
}
```

- [x] **Step 4: Add timeout and partial-output fixtures**

Use a fake `IRemoteSession` to return a timed-out result with partial output. Verify the runner preserves that output, stops later commands, and never reports it as a completed collection. Paging prompts such as `--More--` and `---- More ----` remain the responsibility of the interactive session adapter because `CollectionRunner` deliberately has no protocol-level input/output channel.

- [x] **Step 5: Run orchestration tests**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter CollectionRunnerTests`

Expected: PASS.

## Task 9: Save traceable evidence and render paged PNG files

**Files:**
- Create: `src/AssessmentTool.Core/Evidence/EvidencePathBuilder.cs`
- Create: `src/AssessmentTool.Core/Evidence/EvidenceManifest.cs`
- Create: `tests/AssessmentTool.Core.Tests/Evidence/EvidencePathBuilderTests.cs`
- Create: `src/AssessmentTool.Windows/Evidence/WpfEvidenceRenderer.cs`
- Create: `tests/AssessmentTool.Windows.Tests/Evidence/WpfEvidenceRendererTests.cs`

**Interfaces:**
- Consumes: project/device/check names, exact raw output, timestamps, and execution metadata.
- Produces: deterministic safe paths, `执行记录.json`, `原始输出.txt`, numbered PNG files, and SHA-256 values.

- [x] **Step 1: Test path sanitization and non-overwrite behavior**

```csharp
[Theory]
[InlineData("设备:A/B*?", "设备_A_B__")]
public void Invalid_windows_filename_characters_are_replaced(string input, string expectedPrefix)
{
    var value = new EvidencePathBuilder().SanitizeSegment(input);
    Assert.StartsWith(expectedPrefix, value);
}

[Fact]
public void Repeated_execution_gets_a_new_batch_directory()
{
    var first = Builder().BuildBatchPath(FixedTime);
    var second = Builder().BuildBatchPath(FixedTime);
    Assert.NotEqual(first, second);
}
```

- [x] **Step 2: Run core evidence tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter EvidencePathBuilderTests`

Expected: FAIL because the path builder does not exist.

- [x] **Step 3: Implement safe paths and manifests**

Replace Windows-invalid characters, trim trailing dots/spaces, cap each segment at 80 characters, append an 8-character SHA-256 suffix when shortened, and cap total path length before writing. Write raw output as UTF-8 without BOM. Write files to a temporary name, flush, then rename. Manifest fields include command-pack version, exact command, start/end time, status, raw-output hash, image hashes, and error category.

- [x] **Step 4: Write a Windows PNG pagination test**

```csharp
[Fact]
public void Long_output_creates_numbered_pages_with_matching_hashes()
{
    using var folder = TemporaryFolder.Create();
    var renderer = new WpfEvidenceRenderer(pageWidth: 1400, pageHeight: 900);

    var files = renderer.Render(LongFixtureOutput(300), EvidenceHeader.Fixture(), folder.Path);

    Assert.True(files.Count > 1);
    Assert.EndsWith("证据_001.png", files[0].Path);
    Assert.All(files, file => Assert.Equal(file.Sha256, Sha256.File(file.Path)));
}
```

- [x] **Step 5: Implement WPF rendering**

Use `DrawingVisual`, `FormattedText`, and `RenderTargetBitmap`; do not capture the desktop. Render a header containing project, device, check item, command, timestamp, and page number. Render exact normalized transcript lines in a monospace font. Never invent or summarize output in the PNG.

- [x] **Step 6: Run evidence tests**

Run core: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter EvidencePathBuilderTests`

Run on Windows: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter WpfEvidenceRendererTests`

Expected: PASS.

## Task 10: Discover local and containerized databases read-only

**Files:**
- Create: `src/AssessmentTool.Core/Detection/DatabaseInstanceCandidate.cs`
- Create: `src/AssessmentTool.Core/Detection/HostDatabaseDiscovery.cs`
- Create: `tests/AssessmentTool.Core.Tests/Detection/HostDatabaseDiscoveryTests.cs`
- Create: `tests/fixtures/detection/linux-native-databases.txt`
- Create: `tests/fixtures/detection/linux-container-databases.txt`
- Create: `command-packs/builtin/database-host-discovery-linux.json`

**Interfaces:**
- Consumes: outputs from fixed verified Linux host-discovery commands.
- Produces: `HostDatabaseDiscovery.Detect(IReadOnlyList<CommandOutput>): IReadOnlyList<DatabaseInstanceCandidate>` with product, version, installation type, container/service name, port evidence, confidence, and `RequiresUserConfirmation`.

- [ ] **Step 1: Add local-service and container discovery fixtures**

The native fixture contains representative output from `ps -eo pid,comm,args` and `systemctl list-units --type=service --state=running --no-pager`, including PostgreSQL and MySQL. The container fixture contains JSON-line output from `docker ps --no-trunc --format {{json .}}` and `podman ps --no-trunc --format {{json .}}`, including image tags and published ports. Remove customer names, real addresses, ids, and secrets from fixtures.

- [ ] **Step 2: Write failing discovery tests**

```csharp
[Fact]
public void Detects_native_postgresql_service_and_version()
{
    var outputs = FixtureOutputs.Load("linux-native-databases.txt");

    var candidate = Assert.Single(new HostDatabaseDiscovery().Detect(outputs), item => item.Product == "PostgreSQL");

    Assert.Equal(DatabaseInstallationType.LocalService, candidate.InstallationType);
    Assert.Equal("15", candidate.Version);
    Assert.False(candidate.RequiresUserConfirmation);
}

[Fact]
public void Detects_container_image_but_requires_confirmation_when_version_is_latest()
{
    var outputs = FixtureOutputs.Load("linux-container-databases.txt");

    var candidate = Assert.Single(new HostDatabaseDiscovery().Detect(outputs), item => item.Product == "MySQL");

    Assert.Equal(DatabaseInstallationType.Container, candidate.InstallationType);
    Assert.Null(candidate.Version);
    Assert.True(candidate.RequiresUserConfirmation);
}
```

- [ ] **Step 3: Run discovery tests and verify they fail**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter HostDatabaseDiscoveryTests`

Expected: FAIL because `HostDatabaseDiscovery` does not exist.

- [ ] **Step 4: Implement explicit product signatures**

```csharp
private static readonly DatabaseSignature[] Signatures =
{
    DatabaseSignature.Process("PostgreSQL", @"\bpostgres(?:ql)?(?:[-_ ](?<version>\d+))?\b"),
    DatabaseSignature.Process("MySQL", @"\bmysqld(?:[-_ ](?<version>\d+(?:\.\d+)*))?\b"),
    DatabaseSignature.Process("MariaDB", @"\bmariadbd(?:[-_ ](?<version>\d+(?:\.\d+)*))?\b"),
    DatabaseSignature.Container("PostgreSQL", @"(?:^|/)postgres:(?<version>\d+(?:\.\d+)*)$"),
    DatabaseSignature.Container("MySQL", @"(?:^|/)mysql:(?<version>\d+(?:\.\d+)*)$"),
    DatabaseSignature.Container("MariaDB", @"(?:^|/)mariadb:(?<version>\d+(?:\.\d+)*)$")
};
```

Parse only known command-output formats. Treat `latest`, missing tags, conflicting process/image evidence, and multiple matching instances as requiring user confirmation. Preserve the exact source line as evidence. Do not infer a version from a port number.

- [ ] **Step 5: Add the verified host-discovery command pack**

Include only these exact read-only commands for an authorized Linux host:

```text
ps -eo pid,comm,args
systemctl list-units --type=service --state=running --no-pager
docker ps --no-trunc --format {{json .}}
podman ps --no-trunc --format {{json .}}
```

Mark Docker and Podman commands optional: exit code indicating “not installed” is not a task failure. Do not include `docker exec`, `podman exec`, container lifecycle commands, network scans, or filesystem searches in Phase 1.

- [ ] **Step 6: Run host database discovery tests**

Run: `dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj --filter HostDatabaseDiscoveryTests`

Expected: PASS.

## Task 11: Build the WPF minimum workflow

**Files:**
- Create: `src/AssessmentTool.App/AssessmentTool.App.csproj`
- Create: `src/AssessmentTool.App/App.xaml`
- Create: `src/AssessmentTool.App/App.xaml.cs`
- Create: `src/AssessmentTool.App/MainWindow.xaml`
- Create: `src/AssessmentTool.App/MainWindow.xaml.cs`
- Create: `src/AssessmentTool.App/ViewModels/MainViewModel.cs`
- Create: `src/AssessmentTool.App/ViewModels/DeviceEditorViewModel.cs`
- Create: `src/AssessmentTool.App/ViewModels/CollectionViewModel.cs`
- Create: `src/AssessmentTool.App/Themes/Colors.xaml`
- Create: `src/AssessmentTool.App/Themes/Controls.xaml`
- Create: `tests/AssessmentTool.Windows.Tests/ViewModels/CollectionViewModelTests.cs`

**Interfaces:**
- Consumes: repository, vault, component inspector, collection runner, and evidence renderer.
- Produces: a single-window workflow for project creation, device editing, component status, connection/identification, confirmation, collection progress, stop, and evidence opening.

- [ ] **Step 1: Add the WPF project**

```xml
<Project Sdk="Microsoft.NET.Sdk.WindowsDesktop">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net48</TargetFramework>
    <UseWPF>true</UseWPF>
    <ApplicationIcon>Assets\AssessmentTool.ico</ApplicationIcon>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="../AssessmentTool.Core/AssessmentTool.Core.csproj" />
    <ProjectReference Include="../AssessmentTool.Windows/AssessmentTool.Windows.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Write view-model behavior tests**

```csharp
[Fact]
public async Task Start_is_disabled_until_project_device_component_and_host_key_are_ready()
{
    var viewModel = Fixture().CreateCollectionViewModel();
    Assert.False(viewModel.StartCommand.CanExecute(null));

    viewModel.SelectProject(FixtureProject.Ready);
    viewModel.SelectDevice(FixtureDevice.WithUntrustedHostKeyState);
    Assert.False(viewModel.StartCommand.CanExecute(null));

    viewModel.SelectDevice(FixtureDevice.Ready);
    Assert.True(viewModel.StartCommand.CanExecute(null));
}

[Fact]
public async Task Ambiguous_detection_opens_confirmation_panel_instead_of_executing()
{
    var viewModel = Fixture().CreateCollectionViewModel(ambiguousDetection: true);
    await viewModel.StartAsync();

    Assert.True(viewModel.IsDetectionConfirmationVisible);
    Assert.Empty(viewModel.CompletedCommands);
}
```

- [ ] **Step 3: Run view-model tests and verify they fail**

Run on Windows: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter CollectionViewModelTests`

Expected: FAIL because the view models do not exist.

- [ ] **Step 4: Implement view models without protocol logic**

`CollectionViewModel` exposes bindable state and commands but delegates all work to application services. It never accepts arbitrary remote command text. Error presentation has `Summary`, `PossibleCause`, `RecommendedAction`, and expandable `TechnicalDetails`. Component failures route to the component center rather than crashing.

- [ ] **Step 5: Implement the lightweight visual shell**

Use a left navigation with `首页`, `项目`, `设备`, `采集任务`, `证据`, `命令库`, `组件中心`, and `设置`. Phase 1 enables only implemented pages and labels later pages `后续版本` without dead buttons. Define colors, spacing, typography, focus, disabled, warning, and success states in resource dictionaries. Support light/dark themes and 125%, 150%, and 200% DPI.

- [ ] **Step 6: Run view-model tests and a Windows smoke test**

Run: `dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj --filter CollectionViewModelTests`

Run: `msbuild AssessmentTool.sln /t:Restore,Build /p:Configuration=Release /m`

Expected: tests PASS; solution builds with zero warnings; app opens without administrator rights.

The device identification page also displays discovered database instances from `HostDatabaseDiscovery`. Unknown version, `latest` image tags, conflicting evidence, and multiple instances require an explicit user selection; Phase 1 does not open a direct database session or execute database SQL.

## Task 12: Add the native startup checker, installer, and release verification

**Files:**
- Create: `src/AssessmentTool.Bootstrapper/AssessmentTool.Bootstrapper.vcxproj`
- Create: `src/AssessmentTool.Bootstrapper/main.cpp`
- Create: `installer/AssessmentTool.iss`
- Create: `build/Measure-Package.ps1`
- Create: `tests/fixtures/components/missing-components.json`
- Modify: `AssessmentTool.sln`

**Interfaces:**
- Consumes: Windows version, .NET Framework registry release key, app manifest file, bundled hashes, installer files.
- Produces: Chinese startup remediation before WPF starts, green folder, installer, offline dependency folder convention, and size report.

- [ ] **Step 1: Write the bootstrapper decision table as executable tests**

Extract pure decision logic into `BootstrapDecision.h/.cpp` and use Visual Studio C++ Test or a tiny console test executable. Cover: Windows version unsupported; .NET 4.8 missing; app executable missing; manifest hash mismatch; all checks pass. Expected actions are `ShowUnsupportedWindows`, `ShowDotNetRemediation`, `ShowRepairFiles`, and `LaunchApplication`.

- [ ] **Step 2: Implement the native Win32 checker**

Read the `.NET Framework 4 Full` release key and require release `528040` or later. Verify `AssessmentTool.App.exe` and required bundled tools against a signed build manifest. The repair dialog offers `打开依赖组件文件夹`, `选择离线安装包`, `查看安装说明`, and `退出`; it never downloads or installs without another explicit confirmation.

- [ ] **Step 3: Build the installer script**

`AssessmentTool.iss` installs per-user by default, supports a portable extraction task, includes only required x64 binaries, creates an optional `依赖组件` folder, preserves project data on uninstall, and records install logs. Do not bundle unrelated database drivers in Phase 1.

- [ ] **Step 4: Add package measurement**

```powershell
$files = Get-ChildItem -Path $ReleaseRoot -Recurse -File
$bytes = ($files | Measure-Object -Property Length -Sum).Sum
$largest = $files | Sort-Object Length -Descending | Select-Object -First 20 FullName, Length
[pscustomobject]@{
    TotalBytes = $bytes
    TotalMegabytes = [math]::Round($bytes / 1MB, 2)
    FileCount = $files.Count
    LargestFiles = $largest
} | ConvertTo-Json -Depth 4 | Set-Content "$ReleaseRoot\package-size.json" -Encoding UTF8
```

- [ ] **Step 5: Run final Phase 1 verification on Windows 10 and Windows 11**

Run on each OS:

```powershell
dotnet test tests/AssessmentTool.Core.Tests/AssessmentTool.Core.Tests.csproj
dotnet test tests/AssessmentTool.Windows.Tests/AssessmentTool.Windows.Tests.csproj
msbuild AssessmentTool.sln /t:Restore,Rebuild /p:Configuration=Release /m
iscc installer/AssessmentTool.iss
powershell -ExecutionPolicy Bypass -File build/Measure-Package.ps1 -ReleaseRoot artifacts/portable
```

Expected:

- All tests PASS.
- Build has zero warnings and errors.
- App runs as a standard user.
- Missing Plink and missing .NET paths show Chinese remediation.
- Unknown detection cannot execute collection commands.
- Every unsafe-command fixture is rejected before reaching the fake or real session.
- One authorized SSH fixture produces raw output, manifest JSON, and one or more matching PNG hashes.
- Portable and installer sizes are recorded; if a target is exceeded, `package-size.json` identifies components to split before release.

## Plan Self-Review Results

- Spec coverage for Phase 1: project/device data, SSH password/key architecture, endpoint-bound `SshOptions.HostKeyTrust`, automatic identification, manual fallback, permanent read-only enforcement, command packs, local/container database discovery, raw output, PNG evidence, hashes, dependency checks, green package, installer, and Windows 10/11 verification all map to explicit tasks.
- Deferred by design: Telnet, serial, WinRM, jump hosts, direct database sessions and SQL collection, broad domestic database coverage, middleware, command editor UI, batch import, and production vendor packs each require a separate plan after the MVP closes successfully.
- Type consistency: command, detection, session, collection, repository, evidence, component, and view-model interfaces are introduced before their consumers.
- Placeholder scan: no implementation placeholder is part of a Phase 1 step; deferred subsystems are explicitly outside this plan rather than left incomplete.
