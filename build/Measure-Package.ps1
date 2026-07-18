[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ReleaseRoot,

    [ValidateRange(1, 1024)]
    [int] $TargetMaximumMegabytes = 40
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $ReleaseRoot).Path.TrimEnd('\', '/')
$reportPath = Join-Path $resolvedRoot 'package-size.json'
$files = @(
    Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File |
        Where-Object { -not [string]::Equals(
            $_.FullName,
            $reportPath,
            [System.StringComparison]::OrdinalIgnoreCase) }
)
if ($files.Count -eq 0) {
    throw "Release package does not contain any files: $resolvedRoot"
}

$totalBytes = [long](($files | Measure-Object -Property Length -Sum).Sum)
$maximumBytes = [long]$TargetMaximumMegabytes * 1MB
$largestFiles = @(
    $files |
        Sort-Object Length -Descending |
        Select-Object -First 20 |
        ForEach-Object {
            [pscustomobject]@{
                RelativePath = $_.FullName.Substring($resolvedRoot.Length).TrimStart('\', '/').Replace('\', '/')
                Bytes = [long]$_.Length
                Megabytes = [math]::Round($_.Length / 1MB, 3)
            }
        }
)

$report = [ordered]@{
    FormatVersion = 1
    PackageKind = 'portable-windows-x64'
    GeneratedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    TargetMaximumMegabytes = $TargetMaximumMegabytes
    WithinTarget = $totalBytes -le $maximumBytes
    TotalBytes = $totalBytes
    TotalMegabytes = [math]::Round($totalBytes / 1MB, 2)
    FileCount = $files.Count
    LargestFiles = $largestFiles
}

$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8
$report | ConvertTo-Json -Depth 5

if (-not $report.WithinTarget) {
    throw "Portable package is $($report.TotalMegabytes) MB and exceeds the $TargetMaximumMegabytes MB target. Review package-size.json."
}
