# Source-only experiment. Deliberately no service registration or protected
# Program Files / D:\VERA path mutations. Run manually on an authorized Windows
# host; never elevate to SYSTEM or use a workbridge privilege workaround.
param([switch]$IdentityWindow)

$ErrorActionPreference = 'Stop'
$stageSource = Join-Path $PSScriptRoot '..\ObsessionStopCustodian.cs'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw '64-bit .NET Framework 4.x csc.exe is required; no compilation attempted.'
}
if (-not (Test-Path -LiteralPath $stageSource -PathType Leaf)) {
    throw 'Staging source missing.'
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('VeraObsessionPipeStage-' + [guid]::NewGuid().ToString('N'))
if ($root -match '(?i)\\Program Files\\|\\VERA\\') {
    throw 'Refusing to use a protected or VERA path for this isolated staging test.'
}
$build = Join-Path $root 'build'
$positive = Join-Path $root 'positive'
$collision = Join-Path $root 'collision'
@($build, $positive, $collision) | ForEach-Object {
    [void](New-Item -ItemType Directory -Path $_ -Force)
}
$isolatedSource = Join-Path $build 'ObsessionStopCustodian.Wave12.Stage.cs'
$inputHashBefore = (Get-FileHash -LiteralPath $stageSource -Algorithm SHA256).Hash.ToLowerInvariant()
Copy-Item -LiteralPath $stageSource -Destination $isolatedSource
$inputHashAfter = (Get-FileHash -LiteralPath $stageSource -Algorithm SHA256).Hash.ToLowerInvariant()
$currentHash = (Get-FileHash -LiteralPath $isolatedSource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($inputHashBefore -ne $inputHashAfter -or $inputHashBefore -ne $currentHash) {
    throw 'Staging source changed during snapshot; refusing an unattributable compilation.'
}
$exe = Join-Path $build 'ObsessionStopCustodianStage.exe'
$compile = @('/nologo', '/warnaserror+', '/target:exe',
    '/define:STAGING_SELFTEST,STAGING_PIPE_TEST',
    '/reference:System.ServiceProcess.dll',
    '/reference:System.Web.Extensions.dll',
    ('/out:' + $exe), $isolatedSource)
& $compiler @compile
if ($LASTEXITCODE -ne 0) { throw "Isolated stage compile failed: $LASTEXITCODE" }

$binaryHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt = Join-Path $root 'receipt.txt'
@(
    'STAGING_ONLY=true',
    'CONTACT_DISABLED=true',
    'SCM_INSTALLED=false',
    'PRODUCTION_PIPE_NAMES_USED=false',
    ('STAGE_SOURCE_SHA256=' + $currentHash),
    ('STAGE_BINARY_SHA256=' + $binaryHash),
    ('OS_VERSION=' + [Environment]::OSVersion.VersionString),
    ('PS_VERSION=' + $PSVersionTable.PSVersion.ToString()),
    ('ROOT=' + $root)
) | Set-Content -LiteralPath $receipt -Encoding Ascii

$positiveExe = Join-Path $positive 'ObsessionStopCustodianStage.exe'
Copy-Item -LiteralPath $exe -Destination $positiveExe
$positiveLog = Join-Path $root 'positive.log'
& $positiveExe | Tee-Object -FilePath $positiveLog
$positiveExit = $LASTEXITCODE
Add-Content -LiteralPath $receipt -Value "POSITIVE_EXIT=$positiveExit"
if ($positiveExit -ne 0) { throw "Native byte-pipe transport stage failed: $positiveExit; $root" }
# Exit 0 alone is insufficient. Prove the timeout, disconnect storm,
# successful grant/publish, and post-STOP denial tests really executed.
$positiveLines = @(Get-Content -LiteralPath $positiveLog)
$requiredLines = @(
    'PIPE_TEST publish_before_grant=HOLD|NO_PROTECTED_OWNER_GRANT',
    'PIPE_TEST operator_command_on_publish_pipe=HOLD|INVALID_PUBLISH_REQUEST',
    'PIPE_TEST publish_command_on_operator_pipe=HOLD|UNRECOGNIZED_OPERATOR_COMMAND',
    'PIPE_TEST invalid_expiry=HOLD|EXPIRY_INVALID',
    'PIPE_TEST bad_frame_length=HOLD|MALFORMED_OR_FAILED',
    'PIPE_TEST post_timeout_recovery=HOLD|NO_PROTECTED_OWNER_GRANT',
    'PIPE_TEST abrupt_disconnects=100',
    'PIPE_TEST post_disconnect_burst_recovery=HOLD|NO_PROTECTED_OWNER_GRANT',
    ('PIPE_TEST grant=GRANTED|' + ('d' * 64)),
    ('PIPE_TEST publish=PUBLISHED|' + ('d' * 64)),
    ('PIPE_TEST idempotent_publish=ALREADY_PRESENT|' + ('d' * 64)),
    'PIPE_TEST stop=STOPPED|staging_pipe_generation_0002',
    'PIPE_TEST publish_after_stop=HOLD|STOP_ACTIVE_OR_UNVERIFIED',
    'PIPE_TEST grant_after_stop=HOLD|GENERATION_REVOKED',
    'PIPE_TEST_MODE=STAGING_ONLY;PIPE_NAMESPACE=PROCESS_LOCAL;CONTACT_DISABLED=true;CROSS_IDENTITY_ACL=UNVERIFIED'
)
foreach ($line in $requiredLines) {
    if (@($positiveLines | Where-Object { $_ -ceq $line }).Count -ne 1) {
        throw "Expected exactly one positive stage marker '$line'; $root"
    }
}
if (@($positiveLines | Where-Object {
    $_ -cmatch '^PIPE_TEST whole_frame_timeout=(HOLD\|MALFORMED_OR_FAILED|CLOSED_WITHOUT_ACK)$'
}).Count -ne 1) {
    throw "Expected exactly one fail-closed whole-frame timeout marker; $root"
}
if (@($positiveLines | Where-Object { $_ -cmatch '^PIPE_TEST_FAILURE ' }).Count -ne 0) {
    throw "Positive stage emitted failure markers despite exit 0; $root"
}
Add-Content -LiteralPath $receipt -Value 'REQUIRED_POSITIVE_MARKERS_VERIFIED=true'

$collisionExe = Join-Path $collision 'ObsessionStopCustodianStage.exe'
Copy-Item -LiteralPath $exe -Destination $collisionExe
$priorErrorPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue' # Expected exit 2 writes an intentional security failure.
try {
& $collisionExe --collision 2>&1 | Tee-Object -FilePath (Join-Path $root 'collision.log')
} finally { $ErrorActionPreference = $priorErrorPreference }
$collisionExit = $LASTEXITCODE
Add-Content -LiteralPath $receipt -Value "COLLISION_EXIT=$collisionExit"
# Patched lifecycle must reject a prebound name before acknowledging start.
# The negative collision case therefore PASSes with exit code 0.
if ($collisionExit -ne 0) {
    throw "First-instance fail-closed collision test failed: $collisionExit; $root"
}
if (-not (Select-String -LiteralPath (Join-Path $root 'collision.log') -Pattern '^COLLISION_FAIL_CLOSED=PASS;diagnostic=WIN32_(5|231);START_DENIED_BEFORE_SCM_ACK=true;STAGING_ONLY=true$' -Quiet)) {
    throw "Missing exact fail-closed first-instance collision receipt; $root"
}
$idleDir = Join-Path $root 'idle-stop'
[void](New-Item -ItemType Directory -Path $idleDir)
$idleExe = Join-Path $idleDir 'ObsessionStopCustodianStage.exe'
Copy-Item -LiteralPath $exe -Destination $idleExe
$idleLog = Join-Path $root 'idle-stop.log'
& $idleExe --idle-stop-stress | Tee-Object -FilePath $idleLog
$idleExit = $LASTEXITCODE
Add-Content -LiteralPath $receipt -Value "IDLE_STOP_EXIT=$idleExit"
if ($idleExit -ne 0) { throw "Pending-connect idle stop cancellation failed: $idleExit; $root" }
if (-not (Select-String -LiteralPath $idleLog -SimpleMatch 'PIPE_TEST idle_stop_restarts=40;PENDING_CONNECT_END_REQUIRED=true;STAGING_ONLY=true' -Quiet)) {
    throw "Missing exact 40-iteration idle stop receipt; $root"
}
if ($IdentityWindow) {
    $identityDir = Join-Path $root 'identity'
    [void](New-Item -ItemType Directory -Path $identityDir)
    $identityExe = Join-Path $identityDir 'ObsessionStopCustodianStage.exe'
    Copy-Item -LiteralPath $exe -Destination $identityExe
    & $identityExe --identity-window | Tee-Object -FilePath (Join-Path $root 'identity.log')
    $identityExit = $LASTEXITCODE
    Add-Content -LiteralPath $receipt -Value "IDENTITY_WINDOW_EXIT=$identityExit"
    if ($identityExit -ne 0) { throw "Identity window failed: $identityExit; $root" }
    if (-not (Select-String -LiteralPath (Join-Path $root 'identity.log') -SimpleMatch 'CROSS_IDENTITY_ACL=UNVERIFIED_UNTIL_PROBED' -Quiet)) {
        throw "Missing explicit cross-identity unverified receipt; $root"
    }
}
Write-Output "STAGING_PIPE_RESULT=POSITIVE_PASS_COLLISION_FAIL_CLOSED_PASS"
Write-Output "STAGING_RECEIPT=$receipt"
