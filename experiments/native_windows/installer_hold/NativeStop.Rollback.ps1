# Guarded registry-only rollback for a HUMAN-INITIATED elevated PowerShell.
# Default read-only. Never removes or replaces the custody directory, resident
# SID, STOP/GRANT journals, pinned binary or output artifacts.
# Never run this through a blocked Executor/WorkBridge service-management route.
[CmdletBinding()]
param([switch]$Execute)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Service = 'VeraObsessionStopCustodian'
$Root = 'C:\Program Files\VERA\ObsessionStopCustodian'
$Exe = Join-Path $Root 'ObsessionStopCustodian.exe'
$Sha = 'ddd4622988161de40d4de9a1ce6829b302baa6a9c76ff0de8ac9af96c88735b1'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $Service
$TrustedSids = @('S-1-5-18','S-1-5-32-544')

function Assert-ProtectedCustody([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -cnotcontains $owner) { throw "Custody owner drift: $Path [$owner]" }
    if (-not $acl.AreAccessRulesProtected) { throw "Custody inheritance drift: $Path" }
    $rules = @($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw "Custody ACE count drift: $Path" }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne 'Allow' -or $TrustedSids -cnotcontains $sid -or
            $seen.ContainsKey($sid) -or
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne
             [System.Security.AccessControl.FileSystemRights]::FullControl)) {
            throw "Custody ACE drift: $Path [$sid]"
        }
        $seen[$sid] = $true
    }
    foreach ($sid in $TrustedSids) {
        if (-not $seen.ContainsKey($sid)) { throw "Missing trusted custody ACE: $Path [$sid]" }
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw 'Custody directory absent; not an owned rollback target'
}
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
    throw 'Pinned binary absent; refuse ambiguous rollback'
}
if ((Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha) {
    throw 'Binary hash drift; refuse ambiguous rollback'
}
foreach ($path in @($Root,$Exe,(Join-Path $Root 'output'),
    (Join-Path $Root 'resident.sid'),(Join-Path $Root 'stops.log'),
    (Join-Path $Root 'grants.log'),(Join-Path $Root 'binary.sha256'))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Protected state missing: $path" }
    if (((Get-Item -LiteralPath $path -Force).Attributes -band
          [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse path denied: $path"
    }
    Assert-ProtectedCustody $path
}
$pinText = [System.IO.File]::ReadAllText((Join-Path $Root 'binary.sha256'),
    [System.Text.Encoding]::ASCII).Trim()
if ($pinText -cne $Sha) { throw 'Custody binary.sha256 pin drift; refuse rollback' }
$residentSid = [System.IO.File]::ReadAllText((Join-Path $Root 'resident.sid'),
    [System.Text.Encoding]::ASCII).Trim()
if ([string]::IsNullOrWhiteSpace($residentSid)) { throw 'Custody resident SID empty; refuse rollback' }
[void][System.Security.Principal.SecurityIdentifier]::new($residentSid)
if (-not (Test-Path -LiteralPath $key)) { throw 'Service already absent; nothing to unregister' }
$config = Get-ItemProperty -LiteralPath $key
$expectedQuoted = '"' + $Exe + '"'
if (($config.ImagePath -cne $expectedQuoted -and $config.ImagePath -cne $Exe) -or
    $config.ObjectName -cne 'LocalSystem') { throw 'Service identity/path drift; refuse rollback' }
if ($config.Start -ne 4) { throw 'Service not DISABLED; refuse rollback until independent quiescence' }
$observed = Get-Service -Name $Service -ErrorAction Stop
if ($observed.Status -ne 'Stopped') {
    throw 'Service not STOPPED; refuse to stop a live STOP authority automatically'
}

if (-not $Execute) {
    Write-Output 'DRY_RUN_PASS: native SCM registration is disabled/stopped and exactly bound to pinned custody EXE'
    Write-Output 'WOULD unregister SCM registration only; custody directory, STOP/grant journals, resident SID, binary and output untouched'
    return
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'A human-initiated elevated local Administrator process is required'
}

# This is a user-authored source candidate. There is no equivalent blocked-
# connector execution permitted; no retries if SCM returns an ambiguous result.
& "$env:WINDIR\System32\sc.exe" delete $Service
if ($LASTEXITCODE -ne 0) { throw "SCM delete returned exit=$LASTEXITCODE; inspect manually, do not blind retry" }
if (Test-Path -LiteralPath $key) {
    throw 'SCM key still present/pending deletion; no stronger completion claim'
}
Write-Output 'SCM_UNREGISTERED; all custody files and journals preserved in place'
Write-Output 'HOLD: independent anti-rollback and STOP-governance implications still require review'
