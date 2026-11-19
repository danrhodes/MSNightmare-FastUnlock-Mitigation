#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

# Relaunch in 64-bit PowerShell if the RMM starts 32-bit
if (-not [Environment]::Is64BitProcess) {
    & "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

$Dir    = 'C:\ProgramData\BlockNarrator'
$Log    = "$Dir\run.log"
$Ids    = '{7B1E4C52-3A8D-4F6B-9C21-5D0E8A47B613}', '{9D4088E4-FDED-4700-AD64-45D055EC2947}'
$Active = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
$CiTool = "$env:windir\System32\CiTool.exe"

New-Item $Dir -ItemType Directory -Force | Out-Null

function Log([string]$m) { "{0:s} {1}" -f (Get-Date), $m | Tee-Object -FilePath $Log -Append }

function Invoke-CiTool([string[]]$a) {
    if (-not (Test-Path $CiTool)) { Log 'CiTool.exe missing'; return $false }
    $in = "$Dir\enter.txt"
    '' | Set-Content $in
    $p = Start-Process $CiTool -ArgumentList ($a + '-json') `
         -RedirectStandardInput $in -RedirectStandardOutput "$Dir\ci.out" -RedirectStandardError "$Dir\ci.err" `
         -NoNewWindow -PassThru
    if (-not $p.WaitForExit(60000)) { $p.Kill(); Log 'CiTool timeout'; return $false }
    Log ("CiTool {0} exit {1}" -f ($a -join ' '), $p.ExitCode)
    return ($p.ExitCode -eq 0)
}

try {
    foreach ($id in $Ids) {
        Invoke-CiTool @('--remove-policy', $id) | Out-Null
        Remove-Item "$Active\$id.cip" -Force -ErrorAction SilentlyContinue
    }
    Log 'Block Narrator policy removed.'
    exit 0
}
catch {
    Log "FAILED: $_"
    exit 1
}
