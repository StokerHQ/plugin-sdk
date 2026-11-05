<#
.SYNOPSIS
Builds one hook plugin DLL from one source file (and an optional .rc) with the MSVC command-line tools.

.DESCRIPTION
For a plugin that is a single translation unit, as most are: finds Visual Studio's C++ tools through vswhere,
compiles the resources with rc when an .rc is given, and links a self-contained DLL with the static C runtime and
the SDK's include path. Writes <Out>\<Name>.dll and prints its path.

.EXAMPLE
./Build-HookPlugin.ps1 -Source hook-plugin/my_plugin.cpp -Resources hook-plugin/my_plugin.rc -Name my_plugin -Platform x64 -Out build/x64
#>
param(
    [Parameter(Mandatory)][string]$Source,
    [string]$Resources,
    [Parameter(Mandatory)][string]$Name,
    [ValidateSet('x64', 'Win32')][string]$Platform = 'x64',
    [Parameter(Mandatory)][string]$Out,
    [string[]]$Include = @()
)
$ErrorActionPreference = 'Stop'

$sdkInclude = (Resolve-Path (Join-Path $PSScriptRoot '../include')).Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (!(Test-Path $vswhere)) { throw 'Visual Studio with the C++ tools is required (vswhere.exe not found).' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual Studio C++ tools are required.' }
$arch = if ($Platform -eq 'Win32') { 'x86' } else { 'x64' }

New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$sourcePath = (Resolve-Path $Source).Path
$includes = (@($sdkInclude) + ($Include | ForEach-Object { (Resolve-Path $_).Path }) | ForEach-Object { "/I`"$_`"" }) -join ' '

$commands = @('@echo off', "call `"$vs\VC\Auxiliary\Build\vcvarsall.bat`" $arch >nul", 'if errorlevel 1 exit /b 1')
$res = ''
if ($Resources) {
    $res = "`"$Out\$Name.res`""
    $commands += "rc /nologo /fo $res `"$((Resolve-Path $Resources).Path)`""
    $commands += 'if errorlevel 1 exit /b 1'
}
$commands += "cl /nologo /utf-8 /std:c++20 /EHsc /MT /O2 /W4 /LD /DSTOKER_HOOK_PLUGIN_BUILD $includes `"$sourcePath`" $res /Fo`"$Out\\`" /Fe:`"$Out\$Name.dll`" /link /INCREMENTAL:NO"
$commands += 'if errorlevel 1 exit /b 1'

$batch = Join-Path $Out "build-$Name.cmd"
Set-Content -LiteralPath $batch -Value $commands -Encoding ascii
& cmd.exe /c $batch | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Building $Name exited $LASTEXITCODE." }
Remove-Item $batch
Join-Path $Out "$Name.dll"
