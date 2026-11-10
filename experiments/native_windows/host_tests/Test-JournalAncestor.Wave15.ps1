# Source-only stage: compile in TEMP; synthetic journal bytes and ACL objects.
# No SCM, protected-path mutation, credentials, or recipient effect.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Source)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_ONLY' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64/v4.0.30319/csc.exe'
if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw 'SOURCE_MISSING' }
$stage = Join-Path ([IO.Path]::GetTempPath()) ('ObsessionJournalWave15-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $stage)
$dll = Join-Path $stage 'ObsessionJournalWave15.dll'
& $compiler /nologo /warnaserror+ /target:library /define:STAGING_SELFTEST /reference:System.ServiceProcess.dll /reference:System.Web.Extensions.dll (('/out:') + $dll) $Source
if ($LASTEXITCODE -ne 0) { throw 'WAVE15_CSHARP_STAGE_COMPILE_FAILED' }
$type = [Reflection.Assembly]::LoadFrom($dll).GetType('Vera.ObsessionStop.StopCustodian', $true)
$flags = [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic
$journal = $type.GetMethod('ReadCompleteJournalRows', $flags)
$ancestor = $type.GetMethod('RequireNoUntrustedStructuralRights', $flags)
if ($null -eq $journal -or $null -eq $ancestor) { throw 'WAVE15_METHOD_MISSING' }

function Is-IoFailure($errorRecord) {
    $cause = $errorRecord.Exception.InnerException
    if ($cause -is [Reflection.TargetInvocationException]) { $cause = $cause.InnerException }
    return ($cause -is [System.IO.IOException])
}
function Journal-Allowed([string]$label, [byte[]]$bytes, [int]$count) {
    $path = Join-Path $stage 'synthetic.log'
    [IO.File]::WriteAllBytes($path, $bytes)
    $rows = $journal.Invoke($null, [object[]]@($path.PSObject.BaseObject))
    if ($rows.Length -ne $count) { throw "JOURNAL_WRONG_COUNT:$label" }
    Write-Output ("JOURNAL_TEST $label=ALLOW")
}
function Journal-Denied([string]$label, [byte[]]$bytes) {
    $path = Join-Path $stage 'synthetic.log'
    [IO.File]::WriteAllBytes($path, $bytes)
    try { [void]$journal.Invoke($null, [object[]]@($path.PSObject.BaseObject)) }
    catch {
        if (Is-IoFailure $_) { Write-Output ("JOURNAL_TEST $label=DENIED"); return }
        throw
    }
    throw "JOURNAL_FALSE_ALLOW:$label"
}
$ascii = [Text.Encoding]::ASCII
$nl = [string][char]10
$crlf = [string][char]13 + $nl
$stop = 'STOP|staging_gen_0001|638999111111111111'
$grant = 'GRANT|staging_gen_0001|' + ('a' * 64) + '|' + ('b' * 64) + '|638999111111111111'
Journal-Allowed 'empty_initialized' ([byte[]]@()) 0
Journal-Allowed 'terminated_stop' ($ascii.GetBytes($stop + $nl)) 1
Journal-Allowed 'terminated_grant' ($ascii.GetBytes($grant + $nl)) 1
Journal-Denied 'unterminated_stop' ($ascii.GetBytes($stop))
Journal-Denied 'unterminated_grant' ($ascii.GetBytes($grant))
Journal-Denied 'blank_extra_row' ($ascii.GetBytes($stop + $nl + $nl))
Journal-Denied 'crlf_noncanonical' ($ascii.GetBytes($stop + $crlf))
Journal-Denied 'nonascii_byte' ([byte[]]@(0xff, 0x0a))

$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$untrusted = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-11111111-22222222-33333333-1001')
$trustedInstaller = ([Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller')).Translate(
    [Security.Principal.SecurityIdentifier])
$full = [Security.AccessControl.FileSystemRights]::FullControl
$read = [Security.AccessControl.FileSystemRights]::ReadAndExecute
$deleteChild = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
$allow = [Security.AccessControl.AccessControlType]::Allow
function New-ParentAcl {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($systemSid,$full,$allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($adminSid,$full,$allow))
    return $acl
}
function Parent-Allowed([string]$label,$acl) {
    [void]$ancestor.Invoke($null,[object[]]@($acl.PSObject.BaseObject))
    Write-Output ("ANCESTOR_TEST $label=ALLOW")
}
function Parent-Denied([string]$label,$acl) {
    try { [void]$ancestor.Invoke($null,[object[]]@($acl.PSObject.BaseObject)) }
    catch {
        if (Is-IoFailure $_) { Write-Output ("ANCESTOR_TEST $label=DENIED"); return }
        throw
    }
    throw "ANCESTOR_FALSE_ALLOW:$label"
}
Parent-Allowed 'trusted_exact' (New-ParentAcl)
$readAcl = New-ParentAcl
$readAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($untrusted,$read,$allow))
Parent-Allowed 'untrusted_read_only' $readAcl
$specific = New-ParentAcl
$specific.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($untrusted,$deleteChild,$allow))
Parent-Denied 'specific_delete_child' $specific
$installer = New-ParentAcl
$installer.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($trustedInstaller,$full,$allow))
Parent-Denied 'trustedinstaller_structural_requires_policy' $installer
$inheritOnly = New-ParentAcl
$inheritOnly.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted,$deleteChild,
    [Security.AccessControl.InheritanceFlags]::ContainerInherit,
    [Security.AccessControl.PropagationFlags]::InheritOnly,$allow))
Parent-Allowed 'inherit_only_non_effective' $inheritOnly
Write-Output 'WAVE15_STAGE_RESULT=PASS;SYNTHETIC_ONLY=true;REAL_TOKEN_EFFECTIVE_ACL=UNVERIFIED'
