<#
.SYNOPSIS
Builds one SDK release into dist/: the native zip with its SHA-256, and the .NET packages.

.DESCRIPTION
dist/stoker-plugin-sdk-<version>.zip holds native/ (headers, CMake and MSBuild files, the cl/rc helper, the example
and sdk.json) with LICENSE and README.md beside it. The zip is reproducible - entries in ordinal order, fixed
timestamps, no build output - so the same sources always give the same SHA-256, which is what plugin projects pin.
dist/stoker-plugin-sdk-<version>.zip.sha256 holds that hash. dist/nuget/ holds StokerHQ.Plugins.Registry and the
StokerHQ.Registry tool.

The version is native/sdk.json's.
#>
param([string]$Out = (Join-Path $PSScriptRoot '../dist'), [switch]$SkipPack)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$version = (Get-Content (Join-Path $root 'native/sdk.json') -Raw | ConvertFrom-Json).version
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$zipPath = Join-Path $Out "stoker-plugin-sdk-$version.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }

$native = Join-Path $root 'native'
$entries = @(Get-ChildItem $native -Recurse -File | Where-Object {
        $relative = $_.FullName.Substring($native.Length + 1).Replace('\', '/')
        $relative -notmatch '(^|/)(build/(x64|Win32)|obj|bin)/' -and $relative -notmatch '\.(obj|pdb|ilk|exp|lib|dll|so|res)$'
    } | ForEach-Object { [pscustomobject]@{ Name = $_.FullName.Substring($native.Length + 1).Replace('\', '/'); Path = $_.FullName } })
$entries += [pscustomobject]@{ Name = 'LICENSE'; Path = (Join-Path $root 'LICENSE') }
$entries += [pscustomobject]@{ Name = 'README.md'; Path = (Join-Path $root 'README.md') }
$entries = $entries | Sort-Object { $_.Name } -Culture ([cultureinfo]::InvariantCulture) -CaseSensitive

$stamp = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
$stream = [IO.File]::Open($zipPath, 'CreateNew')
try {
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entry in $entries) {
            $item = $zip.CreateEntry($entry.Name, [IO.Compression.CompressionLevel]::Optimal)
            $item.LastWriteTime = $stamp
            # Line endings as committed (.gitattributes keeps them LF), so a Windows and a Linux checkout give one zip.
            $bytes = [IO.File]::ReadAllBytes($entry.Path)
            $text = $entry.Name -match '\.(h|cpp|cmake|props|json|md|ps1|sh|txt|vcxproj)$|^LICENSE$'
            if ($text) { $bytes = [Text.Encoding]::UTF8.GetBytes(([Text.Encoding]::UTF8.GetString($bytes)).Replace("`r`n", "`n")) }
            $writer = $item.Open()
            try { $writer.Write($bytes, 0, $bytes.Length) } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose() }
} finally { $stream.Dispose() }

$sha = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$zipPath.sha256" -Value "$sha  stoker-plugin-sdk-$version.zip" -Encoding ascii -NoNewline
Write-Host "stoker-plugin-sdk-$version.zip  $sha"

if (!$SkipPack) {
    $nuget = Join-Path $Out 'nuget'
    & dotnet pack (Join-Path $root 'dotnet/StokerPluginSdk.slnx') -c Release -o $nuget -p:ContinuousIntegrationBuild=true --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "dotnet pack exited $LASTEXITCODE." }
    Get-ChildItem $nuget -Filter *.nupkg | ForEach-Object { Write-Host $_.Name }
}
