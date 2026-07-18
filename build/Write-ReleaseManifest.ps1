[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ReleaseRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $GitCommit
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $ReleaseRoot).Path.TrimEnd('\', '/')
$buildInfoPath = Join-Path $resolvedRoot '版本与使用说明.txt'
$manifestPath = Join-Path $resolvedRoot 'SHA256SUMS.txt'
$buildInfo = @(
    'EvaluationTool Windows x64 体验版',
    "Git 提交：$GitCommit",
    "构建时间（UTC）：$([DateTimeOffset]::UtcNow.ToString('O'))",
    '支持系统：Windows 10 / Windows 11 x64',
    '运行方式：完整解压后运行 EvaluationTool.exe',
    '安全边界：自动采集仅执行内置、已校验的只读命令。',
    '首次 SSH 连接必须人工核对完整主机指纹。'
)
Set-Content -LiteralPath $buildInfoPath -Value $buildInfo -Encoding UTF8
Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue

$files = @(
    Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse |
        Where-Object { -not [string]::Equals(
            $_.FullName,
            $manifestPath,
            [System.StringComparison]::OrdinalIgnoreCase) } |
        Sort-Object FullName
)
if ($files.Count -eq 0) {
    throw "Release package does not contain any files: $resolvedRoot"
}

$lines = foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($resolvedRoot.Length).TrimStart('\', '/').Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $relativePath"
}
Set-Content -LiteralPath $manifestPath -Value $lines -Encoding utf8NoBOM

foreach ($line in Get-Content -LiteralPath $manifestPath) {
    if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<path>.+)$') {
        throw "Invalid SHA-256 manifest line: $line"
    }

    $filePath = Join-Path $resolvedRoot $Matches.path
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "Manifest file is missing: $($Matches.path)"
    }

    $actual = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash
    if (-not [string]::Equals($actual, $Matches.hash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest verification failed: $($Matches.path)"
    }
}
