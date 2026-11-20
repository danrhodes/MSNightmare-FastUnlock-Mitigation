#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

if (-not $PSCommandPath) { Write-Host 'Run as a saved script file, not inline'; exit 1 }

# Relaunch in 64-bit PowerShell if the RMM starts 32-bit
if (-not [Environment]::Is64BitProcess) {
    & "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

# Elevation check
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Not elevated'
    exit 1
}

# Single instance (shared with Deploy)
$mtx = New-Object Threading.Mutex($false, 'Global\BlockNarrator')
if (-not $mtx.WaitOne(0)) { Write-Host 'Already running'; exit 1 }

$Dir    = 'C:\ProgramData\BlockNarrator'
$Log    = "$Dir\run.log"
$Id     = '{7B1E4C52-3A8D-4F6B-9C21-5D0E8A47B613}'
$Active = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
$CiTool = "$env:windir\System32\CiTool.exe"

# Working directory: SYSTEM and Administrators only
New-Item $Dir -ItemType Directory -Force | Out-Null
& icacls.exe $Dir /setowner '*S-1-5-32-544' /T /C | Out-Null
& icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null

# Rotate log at 1 MB
if ((Test-Path $Log) -and ((Get-Item $Log).Length -gt 1MB)) { Move-Item $Log "$Log.old" -Force }

function Log([string]$m) {
    $line = "{0:s} {1}" -f (Get-Date), $m
    Add-Content -Path $Log -Value $line
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
