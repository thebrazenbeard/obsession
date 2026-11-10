# Read-only Windows PowerShell 5.1 host and token qualification.
# A denied access request through CreateFileW/OpenService does NOT write or
# change anything; run -Role Resident explicitly under the real resident token.
[CmdletBinding()]
param(
    [ValidateSet('Host','Resident')][string]$Role = 'Host',
    [string]$ResidentSid,
    [switch]$RequireDisabledScm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ServiceName = 'VeraObsessionStopCustodian'
$Root = 'C:\Program Files\VERA\ObsessionStopCustodian'
$Executable = Join-Path $Root 'ObsessionStopCustodian.exe'
$PinnedSha = 'ddd4622988161de40d4de9a1ce6829b302baa6a9c76ff0de8ac9af96c88735b1'
$TrustedSids = @('S-1-5-18','S-1-5-32-544')

if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }

# No token manufacture, impersonation, credential entry, or service mutation.
if ($Role -eq 'Resident') {
    if ([string]::IsNullOrWhiteSpace($ResidentSid)) { throw '-ResidentSid is required' }
    $expected = [System.Security.Principal.SecurityIdentifier]::new($ResidentSid).Value
    $actual = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($actual -cne $expected) {
        throw "WRONG_TOKEN: expected actual resident process SID=$expected, got $actual"
    }
}

# The host can inspect protected custody metadata, journal contents and SCM
# registration. A real non-admin resident *cannot*: that inability is exactly
# what the effective-denial phase needs to verify. Never run this phase with
# the resident token or interpret its failure to read custody as missing state.
function Assert-SafeCustodyParent([string]$Path) {
    # The immediate VERA parent is a structural authority boundary. Broad-SID
    # checks alone miss explicit untrusted users with DELETE_CHILD, CreateFiles,
    # or CreateDirectories. InheritOnly grants do not apply to this directory;
    # the STOP child's own DACL must separately disable inheritance.
    $acl = Get-Acl -LiteralPath $Path
    $owner = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -cnotcontains $owner) { throw "UNTRUSTED_CUSTODY_PARENT_OWNER: $Path [$owner]" }
    $danger = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    foreach ($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (($rule.PropagationFlags -band
             [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        $sid = $rule.IdentityReference.Value
        if ($TrustedSids -cnotcontains $sid -and (($rule.FileSystemRights -band $danger) -ne 0)) {
            throw "UNTRUSTED_CUSTODY_PARENT_STRUCTURAL_ACE: $Path [$sid]"
        }
    }
}

if ($Role -eq 'Host') {
foreach ($path in @('C:\','C:\Program Files','C:\Program Files\VERA', $Root,
    (Join-Path $Root 'output'),$Executable,(Join-Path $Root 'resident.sid'),
    (Join-Path $Root 'binary.sha256'),(Join-Path $Root 'stops.log'),
    (Join-Path $Root 'grants.log'))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "MISSING_CUSTODY_PATH: $path" }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "REPARSE_PATH: $path"
    }
}

Assert-SafeCustodyParent 'C:\Program Files\VERA'

foreach ($path in @($Root,(Join-Path $Root 'output'),$Executable,
    (Join-Path $Root 'resident.sid'),(Join-Path $Root 'binary.sha256'),
    (Join-Path $Root 'stops.log'),(Join-Path $Root 'grants.log'))) {
    $acl = Get-Acl -LiteralPath $path
    $owner = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -cnotcontains $owner) { throw "UNTRUSTED_OWNER: $path [$owner]" }
    if (-not $acl.AreAccessRulesProtected) { throw "INHERITANCE_ENABLED: $path" }
    $rules = @($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    # Do not silently accept an extra deny, an extra conditional ACE, or two
    # copies of SYSTEM while Administrators is absent.
    if ($rules.Count -ne 2) { throw "UNEXPECTED_CUSTODY_ACES: $path" }
    $seen = @{}
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne 'Allow') { throw "DENY_CUSTODY_ACE: $path" }
        $sid = $rule.IdentityReference.Value
        if ($seen.ContainsKey($sid)) { throw "DUPLICATE_CUSTODY_ACE: $path [$sid]" }
        $seen[$sid] = $true
        if ($TrustedSids -cnotcontains $rule.IdentityReference.Value -or
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne
             [System.Security.AccessControl.FileSystemRights]::FullControl)) {
            throw "WEAK_CUSTODY_ACE: $path [$($rule.IdentityReference.Value)]"
        }
    }
    foreach ($trustedSid in $TrustedSids) {
        if (-not $seen.ContainsKey($trustedSid)) { throw "MISSING_CUSTODY_ACE: $path [$trustedSid]" }
    }
}

if ((Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PinnedSha) {
    throw 'INSTALLED_BINARY_HASH_MISMATCH'
}
$pinText = [System.IO.File]::ReadAllText((Join-Path $Root 'binary.sha256'),
    [System.Text.Encoding]::ASCII).Trim()
if ($pinText -cne $PinnedSha) { throw 'PIN_FILE_MISMATCH' }
$configuredSid = [System.IO.File]::ReadAllText((Join-Path $Root 'resident.sid'),
    [System.Text.Encoding]::ASCII).Trim()
if ([string]::IsNullOrWhiteSpace($configuredSid)) { throw 'RESIDENT_SID_EMPTY' }
[void][System.Security.Principal.SecurityIdentifier]::new($configuredSid)
if (-not [string]::IsNullOrWhiteSpace($ResidentSid) -and $configuredSid -cne $ResidentSid) {
    throw 'RESIDENT_SID_CONFIG_DRIFT'
}

$keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName
if (-not (Test-Path -LiteralPath $keyPath)) { throw 'SCM_SERVICE_MISSING' }
$scm = Get-ItemProperty -LiteralPath $keyPath
$quoted = '"' + $Executable + '"'
if (($scm.ImagePath -cne $quoted -and $scm.ImagePath -cne $Executable) -or
    $scm.ObjectName -cne 'LocalSystem') { throw 'SCM_IMAGE_OR_ACCOUNT_DRIFT' }
if ($RequireDisabledScm -and $scm.Start -ne 4) { throw 'SCM_SERVICE_NOT_DISABLED' }
Write-Output "HOST_CUSTODY_PREFLIGHT_PASS installed EXE SHA256=$PinnedSha SCM_account=LocalSystem"
} # Host-only metadata inspection

if ($Role -eq 'Resident') {
    # Open the existing path/request an access mask but perform zero writes.
    # If another process holds an incompatible sharing lock, treat that as
    # UNVERIFIED, not proof of access denial (only Win32 ERROR_ACCESS_DENIED=5).
    $native = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class NativeStopAccessProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateFileW")]
    public static extern SafeFileHandle OpenExisting(string path, uint requested, uint share,
        IntPtr sec, uint disposition, uint flags, IntPtr template);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr OpenSCManager(string machine, string database, uint desired);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr OpenService(IntPtr manager, string name, uint desired);
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseServiceHandle(IntPtr handle);
}
'@
    if (-not ('NativeStopAccessProbe' -as [type])) { Add-Type -TypeDefinition $native }

    function Assert-DeniedOpen([string]$Path, [uint32]$Access) {
        $handle = [NativeStopAccessProbe]::OpenExisting($Path, $Access, 7,
            [IntPtr]::Zero, 3, 0x02000000, [IntPtr]::Zero)
        $errno = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        try {
            if (-not $handle.IsInvalid) { throw "WRITE_CAPABILITY_PRESENT: $Path access=$Access" }
            if ($errno -ne 5) { throw "ACCESS_PROBE_INCONCLUSIVE: $Path access=$Access error=$errno" }
        } finally { $handle.Dispose() }
    }

    # Root and output must resist creation, child deletion, write DAC/owner.
    foreach ($p in @('C:\Program Files\VERA', $Root, (Join-Path $Root 'output'))) {
        foreach ($access in @(2,4,64,65536,262144,524288)) {
            Assert-DeniedOpen $p ([uint32]$access)
        }
    }
    # Existing protected files must resist write/append/delete/retake.
    foreach ($p in @($Executable, (Join-Path $Root 'resident.sid'),
        (Join-Path $Root 'binary.sha256'),(Join-Path $Root 'stops.log'),
        (Join-Path $Root 'grants.log'))) {
        foreach ($access in @(2,4,65536,262144,524288)) {
            Assert-DeniedOpen $p ([uint32]$access)
        }
    }

    $manager = [NativeStopAccessProbe]::OpenSCManager($null,$null,[uint32]1)
    if ($manager -eq [IntPtr]::Zero) { throw 'SCM_ACCESS_PROBE_INCONCLUSIVE_OPEN_MANAGER' }
    try {
        foreach ($access in @(2,16,32,65536,262144,524288)) {
            $svc = [NativeStopAccessProbe]::OpenService($manager,$ServiceName,[uint32]$access)
            $errno = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($svc -ne [IntPtr]::Zero) {
                [void][NativeStopAccessProbe]::CloseServiceHandle($svc)
                throw "RESIDENT_SCM_MANAGEMENT_CAPABILITY_PRESENT: $access"
            }
            if ($errno -ne 5) { throw "SCM_ACCESS_PROBE_INCONCLUSIVE: access=$access error=$errno" }
        }
    } finally { [void][NativeStopAccessProbe]::CloseServiceHandle($manager) }
    Write-Output "RESIDENT_TOKEN_DENIAL_PASS SID=$actual; nonmutating requests denied for protected files/dirs and SCM control"
    Write-Output 'HOLD: this token supplied its own SID; compare it independently against a successful Host-role resident.sid read before treating this as the configured resident'
}

Write-Output "READ_ONLY_PREFLIGHT_PASS role=$Role"
Write-Output 'HOLD: passing ACL/open-right checks does not establish independent STOP, monotonic anti-rollback, or actual named-pipe operation'
