# Source-only candidate for human-initiated Windows PowerShell 5.1 execution.
# Do NOT invoke through an Executor/WorkBridge route that blocks SCM/ACL operations.
# The default mode is read-only. -Execute creates a DISABLED SCM service;
# it does not start a publisher, contact a recipient, or qualify independent STOP.
[CmdletBinding()]
param(
    [string]$SourceExecutable = 'D:\VERA\experiments\obsession-native-stop-custodian-stage-20261109-f5aeb781\ObsessionStopCustodian.Wave11.Candidate2.exe',
    [string]$ResidentSid,
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'VeraObsessionStopCustodian'
$Target = 'C:\Program Files\VERA\ObsessionStopCustodian'
$TargetExe = Join-Path $Target 'ObsessionStopCustodian.exe'
$PinnedBinarySha256 = 'ddd4622988161de40d4de9a1ce6829b302baa6a9c76ff0de8ac9af96c88735b1'
# This is the freshly compiled post-pipe-squatting candidate, NOT a qualified
# host provider. Distinct real Windows tokens, independent operator authority,
# and monotonic STOP anti-rollback require evidence. No caller bypass exists.
$ReleaseHold = 'HOLD_DISTINCT_TOKENS_OPERATOR_SCM_AND_MONOTONIC_STOP_WITNESS_REQUIRED'
$TrustedSids = @('S-1-5-18','S-1-5-32-544')
$BroadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545')
$Dangerous = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

function Assert-NotLink([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse point forbidden: $Path"
    }
}

function Assert-OwnerTrusted([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -cnotcontains $ownerSid) {
        throw "Protected custody owner is not SYSTEM/Administrators: $Path [$ownerSid]"
    }
}

function Assert-NoBroadStructuralRights([string]$Path, [bool]$Strict) {
    $acl = Get-Acl -LiteralPath $Path
    $danger = $Dangerous
    if ($Strict) {
        $danger = $danger -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor
            [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
            [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($BroadSids -contains $rule.IdentityReference.Value -and
            (($rule.FileSystemRights -band $danger) -ne 0)) {
            throw "Broad principal has structurally dangerous access: $Path [$($rule.IdentityReference.Value)]"
        }
    }
}

function Assert-StrictCustodyAcl([string]$Path) {
    Assert-NotLink $Path
    Assert-OwnerTrusted $Path
    Assert-NoBroadStructuralRights $Path $true
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw "ACL inheritance still enabled: $Path" }
    $rules = @($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw "Unexpected custody ACE count: $Path" }
    $seen = @{}
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne 'Allow') { throw "Unexpected custody deny ACE: $Path" }
        $sid = $rule.IdentityReference.Value
        if ($seen.ContainsKey($sid)) { throw "Duplicate custody ACE: $Path [$sid]" }
        $seen[$sid] = $true
        if ($TrustedSids -cnotcontains $rule.IdentityReference.Value -or
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne
             [System.Security.AccessControl.FileSystemRights]::FullControl)) {
            throw "Unexpected custody allow ACE: $Path [$($rule.IdentityReference.Value)]"
        }
    }
    foreach ($trustedSid in $TrustedSids) {
        if (-not $seen.ContainsKey($trustedSid)) { throw "Missing custody ACE: $Path [$trustedSid]" }
    }
}

function Set-StrictCustodyAcl([string]$Path, [bool]$Directory) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    if ($Directory) {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    foreach ($id in $TrustedSids) {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($id)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-StrictCustodyAcl $Path
}

function New-UniqueAsciiFile([string]$Path, [string]$Value) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $stream = [System.IO.FileStream]::new($Path,
        [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Set-StrictCustodyAcl $Path $false
}

function Assert-ResidentSid([string]$InputSid) {
    if ([string]::IsNullOrWhiteSpace($InputSid)) { throw 'Explicit dedicated resident SID is required for -Execute' }
    $sid = [System.Security.Principal.SecurityIdentifier]::new($InputSid)
    if ($sid.Value -cnotmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$') {
        throw 'Resident must be an explicit S-1-5-21 account-form SID; token type still needs live proof'
    }
    if ($TrustedSids -contains $sid.Value -or $BroadSids -contains $sid.Value -or
        @('S-1-5-19','S-1-5-20','S-1-5-7','S-1-5-6','S-1-5-4') -contains $sid.Value) {
        throw 'Resident SID is broad, privileged, or a well-known service/logon identity'
    }
    [void]$sid.Translate([System.Security.Principal.NTAccount]) # no invented SID
    return $sid.Value
}

function Assert-ElevatedLocalAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'A user-initiated, elevated local Administrator PowerShell is required'
    }
}

# Read-only checks run before any effect. This is deliberately a fresh install
# only; a failed/partial install must be independently reconciled, never reset.
if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
foreach ($ancestor in @('C:\','C:\Program Files','C:\Program Files\VERA')) {
    if (-not (Test-Path -LiteralPath $ancestor -PathType Container)) { throw "Ancestor absent: $ancestor" }
    Assert-NotLink $ancestor
    Assert-NoBroadStructuralRights $ancestor $false
}
Assert-OwnerTrusted 'C:\Program Files\VERA'

if (Test-Path -LiteralPath $Target) { throw 'Target exists; refuse overwrite, repair, or journal reinitialization' }
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw 'Service name already registered; refuse collision'
}
if ([string]::IsNullOrWhiteSpace($SourceExecutable)) { throw 'SourceExecutable empty' }
if (-not (Test-Path -LiteralPath $SourceExecutable -PathType Leaf)) { throw 'Source EXE absent' }
Assert-NotLink $SourceExecutable
$sourceSha = (Get-FileHash -LiteralPath $SourceExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceSha -cne $PinnedBinarySha256) { throw 'Source binary SHA256 does not match pinned production artifact' }
if (-not [string]::IsNullOrWhiteSpace($ResidentSid)) { $ResidentSid = Assert-ResidentSid $ResidentSid }

if (-not $Execute) {
    Write-Output "DRY_RUN_PASS native SCM candidate; target absent; source SHA256=$sourceSha; service absent"
    Write-Output 'HOLD: no ACL changes, journal creation, service registration or start performed'
    Write-Output $ReleaseHold
    Write-Output 'HOLD: explicit real resident SID, independent token/effective-rights probes, monotonic STOP witness and operator separation remain release gates'
    return
}

# Hard stop before ANY write. Reviewers must patch this explicit gate only
# after real-token, SCM operator, direct-output denial and monotonic witness
# qualification; a good source build alone does not release this control.
throw $ReleaseHold

Assert-ElevatedLocalAdmin
$ResidentSid = Assert-ResidentSid $ResidentSid

# Effect phase is intentionally fail-stop. On error, preserve all partial files
# and journals; do not erase evidence or blindly retry.
New-Item -Path $Target -ItemType Directory -ErrorAction Stop | Out-Null
Set-StrictCustodyAcl $Target $true
$out = Join-Path $Target 'output'
New-Item -Path $out -ItemType Directory -ErrorAction Stop | Out-Null
Set-StrictCustodyAcl $out $true

Copy-Item -LiteralPath $SourceExecutable -Destination $TargetExe -ErrorAction Stop
Set-StrictCustodyAcl $TargetExe $false
if ((Get-FileHash -LiteralPath $TargetExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $PinnedBinarySha256) { throw 'Copied binary SHA256 drift; service not registered' }

New-UniqueAsciiFile (Join-Path $Target 'resident.sid') ($ResidentSid + "`n")
New-UniqueAsciiFile (Join-Path $Target 'binary.sha256') ($PinnedBinarySha256 + "`n")
New-UniqueAsciiFile (Join-Path $Target 'stops.log') ''
New-UniqueAsciiFile (Join-Path $Target 'grants.log') ''

foreach ($path in @($Target,$out,$TargetExe,(Join-Path $Target 'resident.sid'),
    (Join-Path $Target 'binary.sha256'),(Join-Path $Target 'stops.log'),
    (Join-Path $Target 'grants.log'))) { Assert-StrictCustodyAcl $path }

# Windows PowerShell New-Service defaults to LocalSystem without -Credential.
# The service is DISABLED. No publication process is started.
$quotedBinaryPath = '"' + $TargetExe + '"'
New-Service -Name $ServiceName -BinaryPathName $quotedBinaryPath -DisplayName $ServiceName -StartupType Disabled | Out-Null
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName
$registry = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop
if (($registry.ImagePath -cne $quotedBinaryPath -and $registry.ImagePath -cne $TargetExe) -or
    $registry.ObjectName -cne 'LocalSystem' -or $registry.Start -ne 4) {
    throw 'Registered SCM contract drift; leave service DISABLED and preserve journals for review'
}
Write-Output 'STAGED_ONLY: protected source installed, SCM service registered DISABLED; NOT STARTED'
Write-Output "PINNED_SHA256=$PinnedBinarySha256 RESIDENT_SID=$ResidentSid"
Write-Output 'HOLD: real token ACL/access-denial, operator independence, restart/STOP races and anti-rollback witness unverified'
