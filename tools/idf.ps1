[CmdletBinding()]
param(
    [ValidateSet('build', 'flash', 'monitor', 'reconfigure', 'clean', 'fullclean')]
    [string]$Action = 'build',
    [string]$Port = 'COM5',
    [string]$IdfPath = $env:IDF_PATH,
    [string]$IdfToolsPath = $env:IDF_TOOLS_PATH,
    [int]$Jobs = 0
)

$ErrorActionPreference = 'Stop'

function Assert-LastExitCode {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildDir = Join-Path $RepoRoot 'build\idf6'
$SdkConfig = Join-Path $RepoRoot 'build\sdkconfig.idf6'

if ([string]::IsNullOrWhiteSpace($IdfPath)) {
    $IdfPath = 'E:\Espressif\esp-idf-v6.0.2'
}
if ([string]::IsNullOrWhiteSpace($IdfToolsPath)) {
    $IdfToolsPath = 'E:\Espressif\.espressif'
}

$ExportScript = Join-Path $IdfPath 'export.ps1'
if (-not (Test-Path -LiteralPath $ExportScript)) {
    throw "ESP-IDF export script not found: $ExportScript"
}

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$env:IDF_TOOLS_PATH = $IdfToolsPath
. $ExportScript

# 在外部 ESP-IDF 源码上应用项目维护的兼容 patch；由 git apply 严格检查上下文。
python (Join-Path $RepoRoot 'tools\apply_idf_patches.py') --idf-path $IdfPath
Assert-LastExitCode 'apply_idf_patches'

$IdfArgs = @('-B', $BuildDir, '-D', "SDKCONFIG=$SdkConfig")

switch ($Action) {
    'build' {
        idf.py @IdfArgs reconfigure
        Assert-LastExitCode 'idf.py reconfigure'
        if ($Jobs -le 0) {
            $Jobs = [int]$env:NUMBER_OF_PROCESSORS
            if ($Jobs -le 0) { $Jobs = 4 }
        }
        ninja -C $BuildDir -j $Jobs
        Assert-LastExitCode 'ninja build'
    }
    'flash' {
        idf.py @IdfArgs -p $Port flash
        Assert-LastExitCode 'idf.py flash'
    }
    'monitor' {
        idf.py @IdfArgs -p $Port monitor
        Assert-LastExitCode 'idf.py monitor'
    }
    'reconfigure' {
        idf.py @IdfArgs reconfigure
        Assert-LastExitCode 'idf.py reconfigure'
    }
    'clean' {
        idf.py @IdfArgs clean
        Assert-LastExitCode 'idf.py clean'
    }
    'fullclean' {
        idf.py @IdfArgs fullclean
        Assert-LastExitCode 'idf.py fullclean'
    }
}
