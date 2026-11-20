#Requires -Version 5.1
param([switch]$Child)

# Parent: relaunch self in 64-bit PowerShell. Merge stderr into stdout. Pass the exit code through.
if (-not $Child) {
    $ErrorActionPreference = 'Continue'
    if (-not $PSCommandPath) { Write-Host 'Run as a saved script file, not inline'; exit 1 }
    $ps = if ([Environment]::Is64BitProcess) {
        "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
    } else {
        "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe"
    }
    $out  = & $ps -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Child 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host $out
    exit $code
}

$ErrorActionPreference = 'Stop'

# Elevation check
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Not elevated'
    exit 1
}

# Single instance (shared with Deploy)
$mtx = New-Object Threading.Mutex($false, 'Global\BlockNarrator')
if (-not $mtx.WaitOne(0)) { Write-Host 'Already running'; exit 1 }

# C:\Windows\Logs is not writable by standard users by default
$Dir    = "$env:windir\Logs\BlockNarrator"
$Log    = "$Dir\run.log"
$Id     = '{7B1E4C52-3A8D-4F6B-9C21-5D0E8A47B613}'
$Active = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
$CiTool = "$env:windir\System32\CiTool.exe"

New-Item $Dir -ItemType Directory -Force | Out-Null

# Rotate log at 1 MB
try {
    if ((Test-Path $Log) -and ((Get-Item $Log).Length -gt 1MB)) { Move-Item $Log "$Log.old" -Force }
} catch { }

function Log([string]$m) {
    $line = "{0:s} {1}" -f (Get-Date), $m
    try { Add-Content -Path $Log -Value $line -ErrorAction Stop } catch { }
    Write-Host $line
}

function Invoke-CiTool([string[]]$a, [switch]$NoJson) {
    if (-not (Test-Path $CiTool)) { Log 'CiTool.exe missing'; return $false }
    $in = "$Dir\enter.txt"
    '' | Set-Content $in
    $argList = if ($NoJson) { $a } else { $a + '-json' }
    $p = Start-Process -FilePath $CiTool -ArgumentList $argList `
         -RedirectStandardInput $in -RedirectStandardOutput "$Dir\ci.out" -RedirectStandardError "$Dir\ci.err" `
         -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(60000)) { $p.Kill(); Log 'CiTool timeout'; return $false }
    $p.WaitForExit()
    $code = $p.ExitCode
    $err  = Get-Content "$Dir\ci.err" -Raw -ErrorAction SilentlyContinue
    Log ("CiTool {0} exit [{1}]" -f ($a -join ' '), $code)
    if ($null -eq $code) { return [string]::IsNullOrWhiteSpace($err) }
    if ($code -ne 0) { Log "ci.err: $err" }
    return ($code -eq 0)
}

function Get-PolicyState {
    if (-not (Invoke-CiTool @('--list-policies') -NoJson)) { return 'unknown' }
    $txt = Get-Content "$Dir\ci.out" -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($txt)) { Log 'Policy list output empty'; return 'unknown' }
    $bare  = [regex]::Escape($Id.Trim('{}'))
    $block = ($txt -split '(?m)^Policy:\s*$') | Where-Object { $_ -match "(?im)^\s*Policy ID:\s*$bare\s*$" } | Select-Object -First 1
    if (-not $block) { return 'absent' }
    if ($block -match '(?im)^\s*Is Currently Enforced:\s*true\s*$') { return 'enforced' }
    return 'present'
}

try {
    if (Test-Path $CiTool) {
        if (-not (Invoke-CiTool @('--remove-policy', $Id))) { Log 'WARN: CiTool remove failed' }
    }
    Remove-Item "$Active\$Id.cip" -Force -ErrorAction SilentlyContinue

    if (Test-Path $CiTool) {
        $state = Get-PolicyState
        Log "Policy state after removal: $state"
        if ($state -eq 'enforced' -or $state -eq 'present') {
            Log 'WARN: policy still listed. Reboot to unload.'
            exit 3010
        }
    }

    Log 'Block Narrator policy removed'
    exit 0
}
catch {
    Log "FAILED: $_"
    exit 1
}
