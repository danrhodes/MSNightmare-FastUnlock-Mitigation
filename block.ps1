#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

# Relaunch in 64-bit PowerShell if the RMM starts 32-bit
if (-not [Environment]::Is64BitProcess) {
    & "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

$Dir    = 'C:\ProgramData\BlockNarrator'
$Log    = "$Dir\run.log"
$Id     = '{7B1E4C52-3A8D-4F6B-9C21-5D0E8A47B613}'   # fixed ID: reruns update in place
$Old    = '{9D4088E4-FDED-4700-AD64-45D055EC2947}'   # failed test policy, removed if present
$Xml    = "$Dir\BlockNarrator.xml"
$Cip    = "$Dir\$Id.cip"
$Active = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
$CiTool = "$env:windir\System32\CiTool.exe"

New-Item $Dir -ItemType Directory -Force | Out-Null

function Log([string]$m) { "{0:s} {1}" -f (Get-Date), $m | Tee-Object -FilePath $Log -Append }

function Invoke-CiTool([string[]]$a) {
    if (-not (Test-Path $CiTool)) { Log 'CiTool.exe missing'; return $false }
    $in = "$Dir\enter.txt"
    '' | Set-Content $in                      # answers "Press Enter to Continue"
    $p = Start-Process $CiTool -ArgumentList ($a + '-json') `
         -RedirectStandardInput $in -RedirectStandardOutput "$Dir\ci.out" -RedirectStandardError "$Dir\ci.err" `
         -NoNewWindow -PassThru
    if (-not $p.WaitForExit(60000)) { $p.Kill(); Log 'CiTool timeout'; return $false }
    Log ("CiTool {0} exit {1}" -f ($a -join ' '), $p.ExitCode)
    return ($p.ExitCode -eq 0)
}

try {
    Invoke-CiTool @('--remove-policy', $Old) | Out-Null   # harmless if absent

    Copy-Item "$env:windir\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml" $Xml -Force

    $rule = New-CIPolicyRule -DriverFilePath "$env:windir\System32\Narrator.exe" -Level Hash -Deny
    if (-not $rule) { throw 'Deny rule not created' }
    Merge-CIPolicy -PolicyPaths $Xml -OutputFilePath $Xml -Rules $rule | Out-Null

    Set-CIPolicyIdInfo -FilePath $Xml -PolicyName 'Block Narrator' | Out-Null
    Set-RuleOption -FilePath $Xml -Option 0                  # UMCI on
    Set-RuleOption -FilePath $Xml -Option 3 -Delete          # enforced, not audit

    [xml]$x = Get-Content $Xml
    $x.SiPolicy.PolicyID     = $Id
    $x.SiPolicy.BasePolicyID = $Id
    $x.Save($Xml)

    if (-not (Select-String -Path $Xml -Pattern '<Deny ' -Quiet)) { throw 'No Deny rule in XML' }

    ConvertFrom-CIPolicy -XmlFilePath $Xml -BinaryFilePath $Cip | Out-Null
    New-Item $Active -ItemType Directory -Force | Out-Null
    Copy-Item $Cip "$Active\$Id.cip" -Force

    if (Invoke-CiTool @('--update-policy', $Cip)) { Log 'Policy active'; exit 0 }
    Log 'CiTool failed. Policy staged. Reboot required.'
    exit 3010
}
catch {
    Log "FAILED: $_"
    exit 1
}
