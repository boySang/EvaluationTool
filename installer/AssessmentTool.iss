#define AppName "EvaluationTool 等级保护测评辅助工具"
#define AppPublisher "EvaluationTool"
#define AppExeName "AssessmentTool.App.exe"

#ifndef AppVersion
  #define AppVersion "0.1.0.0"
#endif

#ifndef ReleaseRoot
  #define ReleaseRoot "..\artifacts\release\EvaluationTool"
#endif

#ifndef OutputDir
  #define OutputDir "..\artifacts\installer"
#endif

[Setup]
AppId={{A80DB5B5-2D51-45CE-AF19-74BB39B11A6C}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\EvaluationTool
DefaultGroupName=EvaluationTool
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.10240
OutputDir={#OutputDir}
OutputBaseFilename=EvaluationTool-Setup-windows-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
CloseApplications=yes
RestartApplications=no
ChangesAssociations=no
UsePreviousAppDir=yes
UsePreviousTasks=yes
CreateUninstallRegKey=yes
Uninstallable=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "快捷方式："; Flags: unchecked

[Files]
Source: "{#ReleaseRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\EvaluationTool"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\EvaluationTool"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "启动 EvaluationTool"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[Code]
const
  DotNet48Release = 528040;
  DotNet48DownloadUrl = 'https://dotnet.microsoft.com/download/dotnet-framework/net48';

function HasDotNet48(): Boolean;
var
  ReleaseValue: Cardinal;
begin
  Result := RegQueryDWordValue(
    HKLM32,
    'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full',
    'Release',
    ReleaseValue) and (ReleaseValue >= DotNet48Release);
end;

function InitializeSetup(): Boolean;
var
  Choice: Integer;
  ErrorCode: Integer;
begin
  Result := HasDotNet48();
  if Result then
    exit;

  Choice := MsgBox(
    '本软件需要 Microsoft .NET Framework 4.8。当前电脑未检测到该组件，因此安装已停止。' + #13#10 + #13#10 +
    '是否打开微软官方下载页面？下载和安装前请核对来源，安装过程可能需要管理员权限和重启电脑。' + #13#10 + #13#10 +
    '选择“否”可退出安装，稍后使用离线安装包处理。',
    mbConfirmation,
    MB_YESNO);
  if Choice = IDYES then
    ShellExec('open', DotNet48DownloadUrl, '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
end;
