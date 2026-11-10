# Isolated test: compile source to TEMP, invoke private ACL validator over
# in-memory security objects. No SCM, protected ACL, token, recipient effects.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Source)

$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw 'SIGNED_FRAMEWORK_COMPILER_MISSING'
}
if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    throw 'SOURCE_MISSING'
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('ObsessionStrictAclStage-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temporary)
$dll = Join-Path $temporary 'ObsessionStopCustodianAclStage.dll'
& $compiler /nologo /warnaserror+ /target:library /define:STAGING_SELFTEST /reference:System.ServiceProcess.dll /reference:System.Web.Extensions.dll (('/out:') + $dll) $Source
if ($LASTEXITCODE -ne 0) { throw 'ACL_STAGE_COMPILE_FAILED' }
$assembly = [Reflection.Assembly]::LoadFrom($dll)
$type = $assembly.GetType('Vera.ObsessionStop.StopCustodian', $true)
$flags = [Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic
$method = $type.GetMethod('RequireStrictCustodyAcl', $flags)
if ($null -eq $method) { throw 'STRICT_ACL_METHOD_ABSENT' }

$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$adminsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$unexpectedSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-11111111-22222222-33333333-1001')
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$read = [System.Security.AccessControl.FileSystemRights]::Read
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$deny = [System.Security.AccessControl.AccessControlType]::Deny

function Add-Ace($acl, $sid, $rights, $kind) {
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, $kind)
    $acl.AddAccessRule($rule)
}
function New-TrustedAcl {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    Add-Ace $acl $systemSid $full $allow
    Add-Ace $acl $adminsSid $full $allow
    return $acl
}
function Test-Allowed($label, $acl) {
    # PowerShell pipeline returns can be PSObject-wrapped; pass the exact
    # underlying DirectorySecurity argument to MethodInfo.Invoke.
    [void]$method.Invoke($null, [object[]]@($acl.PSObject.BaseObject))
    Write-Output ('ACL_TEST ' + $label + '=ALLOW')
}
function Test-Denied($label, $acl) {
    try {
        [void]$method.Invoke($null, [object[]]@($acl.PSObject.BaseObject))
    }
    catch {
        # Windows PowerShell wraps MethodInfo.Invoke failures in its own
        # MethodInvocationException instead of exposing TargetInvocationException.
        $cause = $_.Exception.InnerException
        if ($cause -is [Reflection.TargetInvocationException]) {
            $cause = $cause.InnerException
        }
        if ($cause -is [System.IO.IOException]) {
            Write-Output ('ACL_TEST ' + $label + '=DENIED')
            return
        }
        throw
    }
    throw ('ACL_TEST_FALSE_ALLOW: ' + $label)
}

Test-Allowed 'trusted_exact_two' (New-TrustedAcl)
$extraWrite = New-TrustedAcl
Add-Ace $extraWrite $unexpectedSid $full $allow
Test-Denied 'untrusted_specific_fullcontrol' $extraWrite
$extraRead = New-TrustedAcl
Add-Ace $extraRead $unexpectedSid $read $allow
Test-Denied 'untrusted_specific_read' $extraRead
$extraDeny = New-TrustedAcl
Add-Ace $extraDeny $unexpectedSid $read $deny
Test-Denied 'extra_deny' $extraDeny
$inherited = New-TrustedAcl
$inherited.SetAccessRuleProtection($false, $false)
Test-Denied 'unprotected_dacl' $inherited
$weak = New-Object System.Security.AccessControl.DirectorySecurity
$weak.SetAccessRuleProtection($true, $false)
Add-Ace $weak $systemSid $read $allow
Add-Ace $weak $adminsSid $full $allow
Test-Denied 'system_without_fullcontrol' $weak
Write-Output ('ACL_STAGE_RESULT=PASS;SOURCE_ONLY=true;REAL_TOKEN_EFFECTIVE_ACL=UNVERIFIED')
