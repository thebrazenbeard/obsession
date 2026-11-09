# Source-only Windows PowerShell 5.1 negative-test harness. DO NOT auto-run.
# Never sends to a recipient: the only publication is LOCAL_SYNTHETIC_HANDOFF_ONLY.
# Run separately as a true non-admin resident or an independent operator.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Preflight','ResidentDeny','OperatorGrant','ResidentPublish','OperatorStop','ResidentAfterStop')]
    [string]$Mode,
    [string]$Generation,
    [string]$ArtifactId,
    [string]$PayloadPath,
    [switch]$ExecuteTestEffects
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\Program Files\VERA\ObsessionStopCustodian'
$operatorPipe = 'VeraObsessionStopOperatorV1'
$publishPipe = 'VeraObsessionStopPublishV1'
$serviceName = 'VeraObsessionStopCustodian'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

function Emit($status, $detail) {
    [pscustomobject]@{
        mode=$Mode; status=$status; detail=$detail;
        user_sid=$identity.User.Value; elevated_admin=$isAdmin;
        utc=[DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress -Depth 5
}

function Need-Fixture {
    if ($Generation -cnotmatch '^TEST_[A-Za-z0-9_-]{3,91}$') { throw 'Only distinct TEST_ generations are allowed' }
    if ($ArtifactId -cnotmatch '^[0-9a-f]{64}$') { throw 'ArtifactId must be 64 lowercase hex' }
    if (-not $PayloadPath -or -not (Test-Path -LiteralPath $PayloadPath -PathType Leaf)) { throw 'Explicit synthetic PayloadPath required' }
    $bytes = [System.IO.File]::ReadAllBytes($PayloadPath)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt 4096) { throw 'Payload bound 1..4096 failed' }
    $payload = [System.Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    if (-not $payload.EndsWith("`n")) { throw 'Synthetic payload must end in one LF' }
    $body = ConvertFrom-Json -InputObject $payload
    if ($body.schema -cne 'initiative.local-handoff.v1' -or
        $body.scope -cne 'LOCAL_SYNTHETIC_HANDOFF_ONLY' -or
        $body.contact_authorized -cne $false -or $body.delivery_verified -cne $false -or
        $body.proposal.execution_authorized -cne $false -or
        $body.proposal.contact_authorized -cne $false -or
        $body.proposal.target_class -cne 'SYNTHETIC_LOCAL_ONLY') {
        throw 'Payload is not a strictly synthetic contact-disabled fixture'
    }
    return $bytes
}

function Pipe-Roundtrip([string]$name, [string]$message) {
    $stream = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name,
        [System.IO.Pipes.PipeDirection]::InOut,[System.IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $stream.Connect(3000)
        $stream.ReadTimeout = 3000
        $stream.WriteTimeout = 3000
        $request = [System.Text.UTF8Encoding]::new($false,$true).GetBytes($message)
        if ($request.Length -gt 8192) { throw 'Oversized pipe command' }
        $prefix = [byte[]]@( [byte](($request.Length -shr 24) -band 255),
            [byte](($request.Length -shr 16) -band 255),
            [byte](($request.Length -shr 8) -band 255),
            [byte]($request.Length -band 255) )
        $stream.Write($prefix,0,4)
        $stream.Write($request,0,$request.Length)
        $stream.Flush()
        $received = New-Object byte[] 4
        Read-Exact $stream $received 4
        $len = ([int]$received[0] -shl 24) -bor ([int]$received[1] -shl 16) -bor
            ([int]$received[2] -shl 8) -bor [int]$received[3]
        if ($len -lt 1 -or $len -gt 8192) { throw 'Invalid response length' }
        $reply = New-Object byte[] $len
        Read-Exact $stream $reply $len
        return [System.Text.UTF8Encoding]::new($false,$true).GetString($reply)
    } finally { $stream.Dispose() }
}

function Read-Exact($stream, [byte[]]$destination, [int]$count) {
    $offset = 0
    while ($offset -lt $count) {
        $n = $stream.Read($destination,$offset,$count-$offset)
        if ($n -le 0) { throw 'Early pipe EOF' }
        $offset += $n
    }
}

if ($Mode -eq 'Preflight') {
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    $binary=Join-Path $root 'ObsessionStopCustodian.exe'
    $pin=Join-Path $root 'binary.sha256'
    $binaryHash=$null
    $pinMatches=$false
    if ((Test-Path -LiteralPath $binary -PathType Leaf) -and
        (Test-Path -LiteralPath $pin -PathType Leaf)) {
        $binaryHash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        $pinMatches=($binaryHash -ceq ([IO.File]::ReadAllText($pin)).Trim())
    }
    $items = foreach ($p in @('C:\','C:\Program Files','C:\Program Files\VERA',$root,
        (Join-Path $root 'output'),(Join-Path $root 'stops.log'),
        (Join-Path $root 'grants.log'),(Join-Path $root 'resident.sid'),
        (Join-Path $root 'binary.sha256'),(Join-Path $root 'ObsessionStopCustodian.exe'))) {
        if (Test-Path -LiteralPath $p) {
            $acl=Get-Acl -LiteralPath $p
            [pscustomobject]@{path=$p;owner=$acl.Owner;inherit=$acl.AreAccessRulesProtected;
                reparse=[bool]((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint);
                rights=($acl.Access | ForEach-Object {"$($_.IdentityReference):$($_.FileSystemRights):$($_.AccessControlType)"})}
        } else { [pscustomobject]@{path=$p;missing=$true} }
    }
    [pscustomobject]@{mode=$Mode;identity=$identity.Name;sid=$identity.User.Value;
        admin=$isAdmin;service=($service | Select-Object Name,State,StartName,PathName);
        binary_sha256=$binaryHash;binary_pin_matches=$pinMatches;
        paths=$items;read_only=$true} | ConvertTo-Json -Depth 8
    return
}

if (-not $ExecuteTestEffects) { throw 'Effect mode requires -ExecuteTestEffects; never run in production without isolated test identity' }
if ($Mode -like 'Resident*' -and $isAdmin) { throw 'Resident effect test invalid under admin token' }
if ($Mode -like 'Operator*' -and -not $isAdmin) { throw 'Operator effect test requires independently governed operator identity' }

if ($Mode -eq 'ResidentDeny') {
    $svc=Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -eq $svc -or $svc.State -cne 'Running') {
        throw 'Test invalid: native STOP service must already be running'
    }
    $publisher=New-Object System.IO.Pipes.NamedPipeClientStream('.', $publishPipe,
        [System.IO.Pipes.PipeDirection]::InOut)
    try { $publisher.Connect(3000) }
    finally { $publisher.Dispose() }
    try {
        $client=New-Object System.IO.Pipes.NamedPipeClientStream('.', $operatorPipe,
            [System.IO.Pipes.PipeDirection]::InOut)
        try { $client.Connect(1000); throw 'FAIL: resident entered protected operator pipe' }
        finally { $client.Dispose() }
    } catch [UnauthorizedAccessException] { }
    foreach ($protectedState in @('stops.log','grants.log','resident.sid','binary.sha256')) {
        $protectedFile=Join-Path $root $protectedState
        try {
            $f=[IO.File]::Open($protectedFile,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $f.Dispose()
            throw "FAIL: resident opened protected state for write: $protectedState"
        } catch [UnauthorizedAccessException] { }
    }
    $probe=Join-Path $root ('output\.qualification-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $opened=$false
    try {
        $f=[IO.File]::Open($probe,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $opened=$true
        $f.Dispose()
        throw 'FAIL: resident can create protected output files'
    } catch [UnauthorizedAccessException] { }
    finally { if ($opened) { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue } }
    Emit 'PASS' 'Resident connected publisher but operator pipe and protected state/output writes were denied'
    return
}

$payloadBytes=Need-Fixture
$digest=([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($payloadBytes))).Replace('-','').ToLowerInvariant()
if ($Mode -eq 'OperatorGrant') {
    $expiry=[DateTime]::UtcNow.AddMinutes(5).Ticks
    $reply=Pipe-Roundtrip $operatorPipe "GRANT|$Generation|$ArtifactId|$digest|$expiry|V1"
    if ($reply -cne "GRANTED|$ArtifactId" -and $reply -cne 'GRANT_EXISTS') { throw "Grant denied: $reply" }
    Emit 'PASS' "Operator grant admitted $ArtifactId"
} elseif ($Mode -eq 'OperatorStop') {
    $reply=Pipe-Roundtrip $operatorPipe "STOP|$Generation|V1"
    if ($reply -cne "STOPPED|$Generation") { throw "STOP not durably acknowledged: $reply" }
    Emit 'PASS' "STOP acknowledged for $Generation"
} else {
    $cmd='PUBLISH|' + $Generation + '|' + $ArtifactId + '|' +
        [Convert]::ToBase64String($payloadBytes) + '|V1'
    $reply=Pipe-Roundtrip $publishPipe $cmd
    if ($Mode -eq 'ResidentPublish') {
        if ($reply -cne "PUBLISHED|$ArtifactId" -and $reply -cne "ALREADY_PRESENT|$ArtifactId") {
            throw "Baseline protected publish failed: $reply"
        }
    } elseif ($reply -cne 'HOLD|STOP_ACTIVE_OR_UNVERIFIED') {
        throw "FAIL: no exact STOP denial receipt (could just lack grant): $reply"
    }
    Emit 'PASS' "Native publish reply $reply"
}
