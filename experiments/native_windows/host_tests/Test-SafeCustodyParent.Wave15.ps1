# Isolated PowerShell source-function test. Extracts ONLY the named function.
# Mock Get-Acl returns in-memory DirectorySecurity. No protected path/SCM effect.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Source)

$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$sourceText = [IO.File]::ReadAllText($Source)
$ast = [Management.Automation.Language.Parser]::ParseInput(
    $sourceText, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw 'INSTALLER_SOURCE_PARSE_ERROR' }
$matches = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-SafeCustodyParent'
}, $true))
if ($matches.Count -ne 1) { throw 'SAFE_PARENT_FUNCTION_MISSING_OR_DUPLICATE' }
Invoke-Expression $matches[0].Extent.Text

$TrustedSids = @('S-1-5-18','S-1-5-32-544')
$Dangerous = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
$script:FixtureAcl = $null
function Get-Acl { param([string]$LiteralPath) return $script:FixtureAcl }
function New-Acl {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    return $acl
}
function Add-Rule($acl,[string]$identity,$rights,$inheritance,$propagation) {
    $sid = [System.Security.Principal.SecurityIdentifier]::new($identity)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid, $rights, $inheritance, $propagation,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
$none = [System.Security.AccessControl.InheritanceFlags]::None
$propNone = [System.Security.AccessControl.PropagationFlags]::None
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$read = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$append = [System.Security.AccessControl.FileSystemRights]::AppendData
$untrusted = 'S-1-5-21-11111111-22222222-33333333-1001'
$trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

function Base-Acl {
    $acl = New-Acl
    Add-Rule $acl 'S-1-5-18' $full $none $propNone
    Add-Rule $acl 'S-1-5-32-544' $full $none $propNone
    Add-Rule $acl 'S-1-5-32-545' $read $none $propNone
    return $acl
}
function Pass([string]$name,$acl) {
    $script:FixtureAcl = $acl
    Assert-SafeCustodyParent 'X:\ISOLATED-MOCK'
    Write-Output ('PARENT_ACL_TEST ' + $name + '=ALLOW')
}
function Deny([string]$name,$acl) {
    $script:FixtureAcl = $acl
    try {
        Assert-SafeCustodyParent 'X:\ISOLATED-MOCK'
    } catch {
        if ($_.Exception.Message -match '^Untrusted specific principal has structural custody-parent rights:') {
            Write-Output ('PARENT_ACL_TEST ' + $name + '=DENIED')
            return
        }
        throw
    }
    throw ('PARENT_ACL_FALSE_ALLOW: ' + $name)
}

Pass 'trusted_plus_users_read' (Base-Acl)
$specific = Base-Acl
Add-Rule $specific $untrusted $full $none $propNone
Deny 'specific_full_control' $specific
$creator = Base-Acl
$inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
$childInheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
Add-Rule $creator 'S-1-3-0' $full $childInheritance $inheritOnly
Pass 'creator_owner_inherit_only' $creator
$childCreate = Base-Acl
Add-Rule $childCreate $untrusted $append $none $propNone
Deny 'specific_create_subdirectory' $childCreate
$installer = Base-Acl
Add-Rule $installer $trustedInstaller $full $none $propNone
Deny 'trustedinstaller_fullcontrol_policy_hold' $installer
Write-Output 'PARENT_ACL_STAGE=PASS;IN_MEMORY_ONLY=true;REAL_PARENT_EFFECTIVE_ACL=HOLD'
