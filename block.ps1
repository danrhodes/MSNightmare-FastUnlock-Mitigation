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

# Single instance
$mtx = New-Object Threading.Mutex($false, 'Global\BlockNarrator')
if (-not $mtx.WaitOne(0)) { Write-Host 'Already running'; exit 1 }

$Dir    = 'C:\ProgramData\BlockNarrator'
$Log    = "$Dir\run.log"
$Id     = '{7B1E4C52-3A8D-4F6B-9C21-5D0E8A47B613}'   # fixed ID: reruns update in place
$Xml    = "$Dir\BlockNarrator.xml"
$Cip    = "$Dir\$Id.cip"
$Active = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
$CiTool = "$env:windir\System32\CiTool.exe"
$Target = "$env:windir\System32\Narrator.exe"

# Working directory: SYSTEM and Administrators only
New-Item $Dir -ItemType Directory -Force | Out-Null
& icacls.exe $Dir /setowner '*S-1-5-32-544' /T /C | Out-Null
& icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null

# Rotate log at 1 MB
if ((Test-Path $Log) -and ((Get-Item $Log).Length -gt 1MB)) { Move-Item $Log "$Log.old" -Force }

# Logging must not write to the success stream
function Log([string]$m) {
    $line = "{0:s} {1}" -f (Get-Date), $m
    Add-Content -Path $Log -Value $line
    Write-Host $line
}

# Returns exactly one Boolean
function Invoke-CiTool([string[]]$a) {
    if (-not (Test-Path $CiTool)) { Log 'CiTool.exe missing'; return $false }
    $in = "$Dir\enter.txt"
    '' | Set-Content $in                      # answers "Press Enter to Continue"
    $p = Start-Process -FilePath $CiTool -ArgumentList ($a + '-json') `
         -RedirectStandardInput $in -RedirectStandardOutput "$Dir\ci.out" -RedirectStandardError "$Dir\ci.err" `
         -NoNewWindow -PassThru
    if (-not $p.WaitForExit(60000)) { $p.Kill(); Log 'CiTool timeout'; return $false }
    Log ("CiTool {0} exit {1}" -f ($a -join ' '), $p.ExitCode)
    if ($p.ExitCode -ne 0) { Log ('ci.err: ' + (Get-Content "$Dir\ci.err" -Raw -ErrorAction SilentlyContinue)) }
    return ($p.ExitCode -eq 0)
}

# Returns one string: enforced | present | absent | unknown
function Get-PolicyState {
    if (-not (Invoke-CiTool @('--list-policies'))) { return 'unknown' }
    try {
        $j = Get-Content "$Dir\ci.out" -Raw | ConvertFrom-Json
        if ($null -eq $j.Policies) { return 'unknown' }
        $bare = $Id.Trim('{}')
        $pol  = @($j.Policies) | Where-Object { $_.PolicyID -ieq $bare }
        if (-not $pol) { return 'absent' }
        if ($pol.IsEnforced) { return 'enforced' }
        return 'present'
    }
    catch { Log "Policy list parse failed: $_"; return 'unknown' }
}

try {
    if (-not (Test-Path $Target)) { throw "$Target not found" }

    Copy-Item "$env:windir\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml" $Xml -Force

    $rule = New-CIPolicyRule -DriverFilePath $Target -Level Hash -Deny
    if (-not $rule) { throw 'Deny rule not created' }
    Merge-CIPolicy -PolicyPaths $Xml -OutputFilePath $Xml -Rules $rule | Out-Null

    Set-CIPolicyIdInfo -FilePath $Xml -PolicyName 'Block Narrator' | Out-Null
    Set-RuleOption -FilePath $Xml -Option 0                  # UMCI on
    Set-RuleOption -FilePath $Xml -Option 3 -Delete          # enforced, not audit

    [xml]$x = Get-Content $Xml
    $x.SiPolicy.PolicyID     = $Id
    $x.SiPolicy.BasePolicyID = $Id
    $x.Save($Xml)

    # Validate the generated XML
    [xml]$x = Get-Content $Xml
    $ns = New-Object Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('si', $x.DocumentElement.NamespaceURI)
    $deny = $x.SelectNodes('//si:FileRules/si:Deny', $ns)
    if ($deny.Count -lt 1) { throw 'No Deny rule in XML' }
    foreach ($d in $deny) {
        if (-not $x.SelectSingleNode("//si:FileRuleRef[@RuleID='$($d.ID)']", $ns)) { throw "Deny rule $($d.ID) is not referenced" }
    }
    if ($x.SelectNodes('//si:FileRules/si:Allow', $ns).Count -lt 2) { throw 'AllowAll rules missing' }

    ConvertFrom-CIPolicy -XmlFilePath $Xml -BinaryFilePath $Cip | Out-Null

    if (-not (Test-Path $CiTool)) {
        # Older OS: stage the policy. Applies at next boot.
        New-Item $Active -ItemType Directory -Force | Out-Null
        Copy-Item $Cip "$Active\$Id.cip" -Force
        Log 'CiTool missing. Policy staged. Reboot required.'
        exit 3010
    }

    if (-not (Invoke-CiTool @('--update-policy', $Cip))) { throw 'CiTool update failed' }

    $state = 'unknown'
    foreach ($i in 1..3) {
        $state = Get-PolicyState
        if ($state -eq 'enforced') { break }
        Start-Sleep -Seconds 2
    }
    if ($state -ne 'enforced') {
        Log "WARN: update succeeded, policy state: $state"
        exit 4
    }

    # Side-effect check: PowerShell language mode in a new session
    $lm = & "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command '$ExecutionContext.SessionState.LanguageMode'
    Log "PowerShell language mode: $lm"
    if ($lm -ne 'FullLanguage') { Log 'WARN: PowerShell is not in FullLanguage mode' }

    Log 'Policy active and verified'
    exit 0
}
catch {
    Log "FAILED: $_"
    exit 1
}
