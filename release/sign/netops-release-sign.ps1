param(
    [Parameter(Mandatory = $true)][string]$CandidateDir,
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$Cosign,
    [string]$Identity = "325383355+radek-cerny-soukr@users.noreply.github.com",
    [string]$Issuer = "https://github.com/login/oauth",
    [string]$Repository = "radek-cerny-soukr/netops",
    [string]$Registry = "https://ghcr.io",
    [switch]$CheckOnly
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Arches = @("amd64", "arm64")
$Suites = @("blackbox", "redteam", "failclosed", "syslog", "device", "token-output")
$RequiredRows = New-Object System.Collections.ArrayList
foreach ($arch in $Arches) { foreach ($suite in $Suites) { [void]$RequiredRows.Add("actions-$arch-$suite") } }
foreach ($arch in $Arches) { foreach ($role in @("core", "helper", "auditor", "admin")) { [void]$RequiredRows.Add("actions-$arch-engine-$role") } }
$RequiredChecks = New-Object System.Collections.Hashtable ([StringComparer]::Ordinal)
$MinimumVersion = [version]"1.0.4"
$BlindInstallChecks = @("cosign-verify-blob", "sha256sum-check", "container-healthy", "health-ready", "version-is-candidate", "unauthenticated-401", "mcp-tools-list", "audit-without-token")
$BlindUpgradeChecks = @("upgrade-steps-from-docs", "health-ready", "version-is-candidate", "data-preserved", "token-preserved", "ca-preserved")
$BlindRows = @("blind-install-fedora-amd64", "blind-install-debian-amd64", "blind-upgrade-amd64")
$UpgradeRow = "blind-upgrade-amd64"
$UpgradeFromVersion = "1.0.3"
$UpgradeFromImage = "ghcr.io/radek-cerny-soukr/netops@sha256:0ddf246ca5e22f7df89abb9cf8f7c9fd10920eec39b4a02ad7fddac04a3b65ce"
foreach ($row in $BlindRows) {
    [void]$RequiredRows.Add($row)
    if ($row -clike "blind-install-*") { $RequiredChecks[$row] = $BlindInstallChecks } else { $RequiredChecks[$row] = $BlindUpgradeChecks }
}
[void]$RequiredRows.Add("code-review")
$ProtocolRows = @("code-review") + $BlindRows
$OptionalRows = @("codex-cli-e2e")
$KnownSeverities = @("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
$BlockingSeverities = @("High", "Critical")
$ReportStatuses = @("PASS", "FAIL", "NOT RUN")
$BuildTimeFormats = [string[]]@("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", "yyyy-MM-dd'T'HH:mm:sszzz", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz")

$script:Rows = New-Object System.Collections.ArrayList

function Add-Row([string]$Area, [string]$Status, [string]$Detail, [bool]$Optional = $false) {
    [void]$script:Rows.Add([pscustomobject]@{ Area = $Area; Status = $Status; Detail = $Detail; Optional = $Optional })
}

function Get-Sha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Read-Json([string]$Path) {
    return (Get-Content -Raw -Encoding UTF8 -LiteralPath $Path | ConvertFrom-Json)
}

function Get-JsonString([byte[]]$Bytes, [string[]]$Names) {
    Add-Type -AssemblyName System.Text.Json
    $stream = New-Object System.IO.MemoryStream (, $Bytes)
    try {
        $document = [System.Text.Json.JsonDocument]::Parse($stream, (New-Object System.Text.Json.JsonDocumentOptions))
        try {
            $element = $document.RootElement
            foreach ($name in $Names) {
                if ($element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $null }
                $matched = @($element.EnumerateObject() | Where-Object { $_.Name -ceq $name })
                if ($matched.Count -ne 1) { return $null }
                $element = $matched[0].Value
            }
            if ($element.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { return $null }
            return $element.GetString()
        }
        finally { $document.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Has-Property($Object, [string]$Name) {
    return ($null -ne $Object) -and ($Object -is [System.Management.Automation.PSCustomObject]) -and ($null -ne $Object.PSObject.Properties[$Name])
}

function Get-Http([string]$Url, [hashtable]$Headers) {
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = "GET"
    $request.AllowAutoRedirect = $true
    $request.Timeout = 30000
    foreach ($key in $Headers.Keys) {
        if ($key -eq "Accept") { $request.Accept = $Headers[$key] } else { $request.Headers.Add($key, $Headers[$key]) }
    }
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        if ($_.Exception.Response) { return @{ Status = [int]$_.Exception.Response.StatusCode; Bytes = [byte[]]@() } }
        throw
    }
    try {
        $stream = $response.GetResponseStream()
        $memory = New-Object System.IO.MemoryStream
        $stream.CopyTo($memory)
        return @{ Status = [int]$response.StatusCode; Bytes = $memory.ToArray() }
    }
    finally { $response.Close() }
}

function Test-Link($Item) {
    return (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or ($null -ne $Item.LinkType)
}

function Test-WindowsHost {
    if (Test-Path variable:IsWindows) { return $IsWindows }
    return $true
}

function Test-PrivateDir([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or (Test-Link $item) -or @(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) { return $false }
    if (Test-WindowsHost) {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $sid = [System.Security.Principal.SecurityIdentifier]
        $acl = Get-Acl -LiteralPath $Path
        $rules = @($acl.GetAccessRules($true, $true, $sid))
        if ($acl.GetOwner($sid).Value -cne $user.Value -or -not $acl.AreAccessRulesProtected -or $rules.Count -ne 1) { return $false }
        return ($rules[0].IdentityReference.Value -ceq $user.Value) -and ($rules[0].AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and ($rules[0].FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) -and (-not $rules[0].IsInherited)
    }
    return ($item.UnixFileMode -eq [IO.UnixFileMode]"UserRead, UserWrite, UserExecute") -and ($item.UnixStat.UserId -eq (Get-Item -LiteralPath "/proc/self/status").UnixStat.UserId)
}

function New-SnapshotDir([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw ("snapshot directory already exists: " + $Path) }
    if (Test-WindowsHost) {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $security.SetOwner($user)
        $security.SetAccessRuleProtection($true, $false)
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit", [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)))
        if ($PSVersionTable.PSEdition -ceq "Desktop") { [void][IO.Directory]::CreateDirectory($Path, $security) }
        else { [void][IO.FileSystemAclExtensions]::CreateDirectory($security, $Path) }
    }
    else { [void][IO.Directory]::CreateDirectory($Path, [IO.UnixFileMode]"UserRead, UserWrite, UserExecute") }
    if (-not (Test-PrivateDir $Path)) { throw ("snapshot directory is not a new private directory of the current user: " + $Path) }
}

function Write-NewFile([string]$Path, [byte[]]$Bytes) {
    $stream = New-Object System.IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}

function Copy-Snapshot([string]$Dir, [string]$Snapshot) {
    $count = 0
    foreach ($entry in (Get-ChildItem -LiteralPath $Dir -Force)) {
        if (Test-Link $entry) { Add-Row "snapshot" "FAIL" ($entry.Name + " is a link or reparse point"); return $false }
        if ($entry.PSIsContainer) { Add-Row "snapshot" "FAIL" ($entry.Name + " is a directory"); return $false }
        if ($entry.Name -cnotmatch '\A[A-Za-z0-9._-]+\z') { Add-Row "snapshot" "FAIL" ("unsafe name " + $entry.Name); return $false }
        if ($entry -isnot [IO.FileInfo] -or ($entry.Attributes -band [IO.FileAttributes]::Device) -ne 0 -or $entry.Length -eq 0) { Add-Row "snapshot" "FAIL" ($entry.Name + " is empty or not a regular file"); return $false }
        $bytes = [IO.File]::ReadAllBytes($entry.FullName)
        if ($bytes.Length -ne $entry.Length) { Add-Row "snapshot" "FAIL" ($entry.Name + " changed while it was copied"); return $false }
        Write-NewFile (Join-Path $Snapshot $entry.Name) $bytes
        $count++
    }
    Add-Row "snapshot" "PASS" ([string]$count + " files copied once into a private snapshot; all checks and the signature use only the snapshot")
    return $true
}

function Test-CandidateDir([string]$Dir) {
    $root = Get-Item -LiteralPath $Dir -Force
    if (Test-Link $root) { Add-Row "candidate directory" "FAIL" "the candidate directory is a link or reparse point"; return $false }
    foreach ($entry in (Get-ChildItem -LiteralPath $Dir -Force)) {
        if (Test-Link $entry) { Add-Row "candidate directory" "FAIL" ($entry.Name + " is a link or reparse point"); return $false }
        if ($entry.PSIsContainer) { Add-Row "candidate directory" "FAIL" ($entry.Name + " is a directory"); return $false }
    }
    Add-Row "candidate directory" "PASS" "regular files only, no links, reparse points or directories"
    return $true
}

function Test-ReleaseDocs([string]$Root, [string]$Version) {
    $open = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { Add-Row "release documentation" "FAIL" ("source checkout not found: " + $Root); return }
    $base = (Resolve-Path -LiteralPath $Root).Path.TrimEnd([char[]]@('/', '\'))
    $notes = "release/notes-" + $Version + ".md"
    if (-not (Test-Path -LiteralPath (Join-Path $base $notes) -PathType Leaf)) { [void]$open.Add($notes + " is missing") }
    $changelog = Join-Path $base "CHANGELOG.md"
    $heading = '\A## ' + [regex]::Escape($Version) + ' - [0-9]{4}-[0-9]{2}-[0-9]{2}\z'
    if (-not (Test-Path -LiteralPath $changelog -PathType Leaf) -or @([IO.File]::ReadAllLines($changelog) | Where-Object { $_ -cmatch $heading }).Count -eq 0) { [void]$open.Add("CHANGELOG.md has no dated section ## " + $Version + " - YYYY-MM-DD") }
    $dirs = New-Object System.Collections.Queue
    $dirs.Enqueue($base)
    while ($dirs.Count -gt 0) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $dirs.Dequeue() -Force | Sort-Object Name)) {
            $relative = $entry.FullName.Substring($base.Length + 1).Replace('\', '/')
            if ($entry.PSIsContainer) {
                if (-not (Test-Link $entry) -and @(".git", "node_modules") -cnotcontains $entry.Name -and $relative -cne "docs/archive") { $dirs.Enqueue($entry.FullName) }
            }
            elseif ($entry.Name -clike "*.md") {
                $number = 0
                foreach ($line in [IO.File]::ReadAllLines($entry.FullName)) {
                    $number++
                    foreach ($match in [regex]::Matches($line, 'TODO\(([^)\s]{0,64})\)?')) { [void]$open.Add($relative + ":" + $number + ": open placeholder TODO(" + $match.Groups[1].Value + ")") }
                }
            }
        }
    }
    if ($open.Count -eq 0) { Add-Row "release documentation" "PASS" ("notes, dated changelog section and no TODO( placeholder in the Markdown of " + $base) }
    else { Add-Row "release documentation" "FAIL" ($open -join "; ") }
}

function Read-Sums([string]$Dir, [string]$SumsPath) {
    $listed = New-Object System.Collections.Hashtable ([StringComparer]::Ordinal)
    foreach ($line in (Get-Content -LiteralPath $SumsPath)) {
        if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$') { Add-Row "checksums" "FAIL" ("malformed or unsafe line: " + $line); return $null }
        $hash = $Matches[1]; $name = $Matches[2]
        if ($name -match '\.\.') { Add-Row "checksums" "FAIL" ("unsafe name " + $name); return $null }
        if ($listed.ContainsKey($name)) { Add-Row "checksums" "FAIL" ("duplicate entry " + $name); return $null }
        $path = Join-Path $Dir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Add-Row "checksums" "FAIL" ($name + " listed but missing"); return $null }
        $item = Get-Item -LiteralPath $path -Force
        if (Test-Link $item) { Add-Row "checksums" "FAIL" ($name + " is a link or reparse point"); return $null }
        if ((Get-FileSha256 $path) -cne $hash) { Add-Row "checksums" "FAIL" ($name + " SHA-256 differs"); return $null }
        $listed[$name] = $hash
    }
    $sumsName = Split-Path -Leaf $SumsPath
    $bundleName = $sumsName + ".sigstore.json"
    foreach ($file in (Get-ChildItem -LiteralPath $Dir -Force)) {
        if ($file.Name -ceq $sumsName -or $file.Name -ceq $bundleName) { continue }
        if (-not $listed.ContainsKey($file.Name)) { Add-Row "checksums" "FAIL" ($file.Name + " is in the candidate directory but not in the signed checksum list"); return $null }
    }
    Add-Row "checksums" "PASS" ([string]$listed.Count + " files match the checksum list; no unlisted, linked or duplicate files")
    return $listed
}

function Test-Manifest($Manifest, $Listed, [string]$ManifestName) {
    if ($Manifest.schema -isnot [string] -or $Manifest.product -isnot [string] -or $Manifest.version -isnot [string] -or $Manifest.schema -cne "netops-release-candidate/1" -or $Manifest.product -cne "netops" -or $Manifest.version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+\z') {
        Add-Row "manifest" "FAIL" "unknown schema, product or version"; return $false
    }
    $parsedVersion = $null
    if (-not [version]::TryParse($Manifest.version, [ref]$parsedVersion) -or $parsedVersion -lt $MinimumVersion) {
        Add-Row "manifest" "FAIL" ("this signing tool signs netops " + $MinimumVersion + " and later, not " + $Manifest.version + "; use the tool from the commit of that release"); return $false
    }
    if ($Manifest.source.repository -isnot [string] -or $Manifest.source.commit -isnot [string] -or $Manifest.source.repository -cne $Repository -or $Manifest.source.commit -cnotmatch '^[0-9a-f]{40}\z') {
        Add-Row "manifest" "FAIL" "repository or commit invalid"; return $false
    }
    if ($Manifest.image.index_digest -isnot [string] -or $Manifest.image.index_digest -cnotmatch '^sha256:[0-9a-f]{64}\z') { Add-Row "manifest" "FAIL" "index digest invalid"; return $false }
    foreach ($required in @($ManifestName, "compose.yaml", "env.example")) {
        if (-not $Listed.ContainsKey($required)) { Add-Row "manifest" "FAIL" ($required + " not covered by the checksum list"); return $false }
    }
    foreach ($name in @("compose.yaml", "env.example")) {
        if ($Manifest.release_files.$name -isnot [string] -or $Manifest.release_files.$name -cne $Listed[$name]) { Add-Row "manifest" "FAIL" ("release_files." + $name + " differs from the checksum list"); return $false }
    }
    foreach ($arch in $Arches) {
        $platform = $Manifest.image.platforms.$arch
        if ($null -eq $platform -or $platform.digest -isnot [string] -or $platform.digest -cnotmatch '^sha256:[0-9a-f]{64}\z') { Add-Row "manifest" "FAIL" ("platform " + $arch + " missing or malformed"); return $false }
        foreach ($kind in @("sbom", "scan", "gate")) {
            $file = $platform.files.$kind
            if (-not $Listed.ContainsKey($file.file) -or $Listed[$file.file] -cne $file.sha256) { Add-Row "manifest" "FAIL" ($file.file + " differs from the checksum list"); return $false }
        }
    }
    Add-Row "manifest" "PASS" ("netops " + $Manifest.version + ", commit " + $Manifest.source.commit + ", index " + $Manifest.image.index_digest)
    return $true
}

function Test-PinnedEnv([string]$Dir, $Manifest) {
    $expected = "NETOPS_IMAGE=" + $Manifest.image.name + "@" + $Manifest.image.index_digest
    $lines = @(Get-Content -LiteralPath (Join-Path $Dir "env.example") | Where-Object { $_ -like "NETOPS_IMAGE=*" })
    if ($lines.Count -eq 1 -and $lines[0] -ceq $expected) { Add-Row "pinned image" "PASS" $expected }
    else { Add-Row "pinned image" "FAIL" ("env.example does not pin " + $expected) }
}

function Test-Registry($Manifest) {
    $name = $Manifest.image.name
    if ($name -isnot [string] -or $name -cne ("ghcr.io/" + $Repository)) { Add-Row "registry" "FAIL" ("image " + $name + " is not ghcr.io/" + $Repository); return }
    $path = $Repository
    $token = Get-Http ($Registry + "/token?scope=repository:" + $path + ":pull") @{}
    if ($token.Status -ne 200) { Add-Row "registry" "FAIL" ("anonymous pull token refused: HTTP " + $token.Status); return }
    $bearer = (ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($token.Bytes))).token
    $accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"
    $index = Get-Http ($Registry + "/v2/" + $path + "/manifests/" + $Manifest.image.index_digest) @{ Accept = $accept; Authorization = ("Bearer " + $bearer) }
    if ($index.Status -ne 200) { Add-Row "registry" "FAIL" ("index not readable anonymously: HTTP " + $index.Status + " (is the package public?)"); return }
    $digest = "sha256:" + (Get-Sha256Hex $index.Bytes)
    if ($digest -cne $Manifest.image.index_digest) { Add-Row "registry" "FAIL" ("index bytes hash to " + $digest); return }
    $parsed = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($index.Bytes))
    $found = New-Object System.Collections.Hashtable ([StringComparer]::Ordinal)
    foreach ($entry in $parsed.manifests) {
        if ($entry.platform.os -cne "linux") { Add-Row "registry" "FAIL" "index carries a non-linux entry"; return }
        if ($found.ContainsKey($entry.platform.architecture)) { Add-Row "registry" "FAIL" "index repeats an architecture"; return }
        $found[$entry.platform.architecture] = $entry.digest
    }
    if ($found.Count -ne 2 -or $found["amd64"] -cne $Manifest.image.platforms.amd64.digest -or $found["arm64"] -cne $Manifest.image.platforms.arm64.digest) {
        Add-Row "registry" "FAIL" "index platforms differ from the candidate manifest"; return
    }
    Add-Row "registry" "PASS" ("public index " + $digest + " binds amd64 and arm64")
}

function Test-Vulnerabilities([string]$Dir, $Manifest, $Listed) {
    $assessmentName = "netops-" + $Manifest.version + "-vulnerability-assessments.json"
    $assessed = New-Object System.Collections.Hashtable ([StringComparer]::Ordinal)
    if ($Listed.ContainsKey($assessmentName)) {
        foreach ($item in (Read-Json (Join-Path $Dir $assessmentName))) {
            if ((Has-Property $item "exploitable") -and ($item.exploitable -is [bool]) -and (-not $item.exploitable) -and (Has-Property $item "reasoning") -and ($item.reasoning -is [string]) -and (-not [string]::IsNullOrWhiteSpace($item.reasoning)) -and (Has-Property $item "evidence") -and ($item.evidence -is [string]) -and (-not [string]::IsNullOrWhiteSpace($item.evidence))) {
                $assessed[[string]::Join("|", @($item.id, $item.package, $item.version, $item.type))] = $true
            }
        }
    }
    foreach ($arch in $Arches) {
        $platform = $Manifest.image.platforms.$arch
        $gate = Read-Json (Join-Path $Dir $platform.files.gate.file)
        if (@("pass", "needs-assessment") -cnotcontains $gate.status) { Add-Row ("vulnerabilities " + $arch) "FAIL" ("gate status " + $gate.status); continue }
        $scan = Read-Json (Join-Path $Dir $platform.files.scan.file)
        if (-not (Has-Property $scan "matches") -or -not ($scan.PSObject.Properties["matches"].Value -is [System.Array])) {
            Add-Row ("vulnerabilities " + $arch) "FAIL" "raw scan matches is not a JSON array"; continue
        }
        $built = $null
        $builtNames = $null
        if ((Has-Property $scan "descriptor") -and (Has-Property $scan.descriptor "db")) {
            $holders = New-Object System.Collections.ArrayList
            if (Has-Property $scan.descriptor.db "status") { [void]$holders.Add([pscustomobject]@{ Holder = $scan.descriptor.db.status; Names = [string[]]@("descriptor", "db", "status", "built") }) }
            [void]$holders.Add([pscustomobject]@{ Holder = $scan.descriptor.db; Names = [string[]]@("descriptor", "db", "built") })
            foreach ($entry in $holders) {
                $holder = $entry.Holder
                if ($null -cne $holder -and (Has-Property $holder "built") -and $holder.built) { $built = $holder.built; $builtNames = $entry.Names; break }
            }
        }
        $gateBuilt = $null
        if (Has-Property $gate "database_built") { $gateBuilt = $gate.database_built }
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $scanBytes = [IO.File]::ReadAllBytes((Join-Path $Dir $platform.files.scan.file))
            $gateBytes = [IO.File]::ReadAllBytes((Join-Path $Dir $platform.files.gate.file))
            if ((Get-Sha256Hex $scanBytes) -cne $Listed[$platform.files.scan.file] -or (Get-Sha256Hex $gateBytes) -cne $Listed[$platform.files.gate.file]) { Add-Row ("vulnerabilities " + $arch) "FAIL" "raw scan or gate result differs from the checksum list"; continue }
            if ($null -ne $builtNames) { $built = Get-JsonString $scanBytes $builtNames }
            if ($null -ne $gateBuilt) { $gateBuilt = Get-JsonString $gateBytes ([string[]]@("database_built")) }
        }
        $builtTime = [DateTimeOffset]::MinValue
        if ($built -isnot [string] -or -not [DateTimeOffset]::TryParseExact($built, $BuildTimeFormats, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$builtTime)) { Add-Row ("vulnerabilities " + $arch) "FAIL" "raw scan does not name a parseable database build time"; continue }
        if (-not (Has-Property $gate "database_built") -or $gateBuilt -isnot [string] -or $built -cne $gateBuilt -or -not (Has-Property $gate "database_age_hours") -or [double]$gate.database_age_hours -gt 48 -or [double]$gate.database_age_hours -lt -1) {
            Add-Row ("vulnerabilities " + $arch) "FAIL" ("database build " + $built + " does not match a fresh gate result (age at scan must be 0..48 h)"); continue
        }
        if ($builtTime -gt [DateTimeOffset]::UtcNow.AddHours(1)) { Add-Row ("vulnerabilities " + $arch) "FAIL" "database build time lies in the future"; continue }
        $target = $scan.source.target
        $expectedRef = $Manifest.image.name + "@" + $platform.digest
        if ($target.userInput -isnot [string] -or $target.userInput -cne $expectedRef -or @($target.repoDigests | Where-Object { $_ -isnot [string] }).Count -ne 0 -or @($target.repoDigests) -cnotcontains $expectedRef) {
            Add-Row ("vulnerabilities " + $arch) "FAIL" ("raw scan is not of " + $expectedRef); continue
        }
        $fixable = New-Object System.Collections.ArrayList
        $missing = New-Object System.Collections.ArrayList
        $count = 0
        $malformed = $false
        foreach ($match in $scan.matches) {
            $severity = [string]$match.vulnerability.severity
            if ($KnownSeverities -cnotcontains $severity -or -not $match.vulnerability.id -or -not $match.artifact.name -or -not $match.artifact.version -or -not $match.artifact.type) { $malformed = $true; break }
            $count++
            $key = [string]::Join("|", @($match.vulnerability.id, $match.artifact.name, $match.artifact.version, $match.artifact.type))
            if ($BlockingSeverities -ccontains $severity -and $match.vulnerability.fix.state -ceq "fixed") { if (-not $fixable.Contains($key)) { [void]$fixable.Add($key) }; continue }
            if (-not $assessed.ContainsKey($key) -and -not $missing.Contains($key)) { [void]$missing.Add($key) }
        }
        if ($malformed) { Add-Row ("vulnerabilities " + $arch) "FAIL" "raw scan has a finding with unknown severity or missing id, package, version or type" }
        elseif ($fixable.Count -gt 0) { Add-Row ("vulnerabilities " + $arch) "FAIL" ("fixable High/Critical: " + ($fixable -join ", ")) }
        elseif ($missing.Count -gt 0) { Add-Row ("vulnerabilities " + $arch) "FAIL" ("not assessed for this exact package version: " + ($missing -join ", ")) }
        else { Add-Row ("vulnerabilities " + $arch) "PASS" ([string]$count + " findings in the raw scan of " + $platform.digest + " (database " + $built + "), each with a non-exploitability assessment for its exact version") }
    }
}

function Test-Acceptance([string]$Dir, $Manifest, $Listed) {
    $acceptanceName = "netops-" + $Manifest.version + "-acceptance-manifest.json"
    if (-not $Listed.ContainsKey($acceptanceName)) { Add-Row "acceptance" "FAIL" ("missing signed " + $acceptanceName); return }
    $acceptance = Read-Json (Join-Path $Dir $acceptanceName)
    if ($acceptance.schema -isnot [string] -or $acceptance.candidate_commit -isnot [string] -or $acceptance.candidate_image -isnot [string] -or $acceptance.schema -cne "netops-acceptance-manifest/1" -or $acceptance.candidate_commit -cne $Manifest.source.commit -or $acceptance.candidate_image -cne $Manifest.image.index_digest) {
        Add-Row "acceptance" "FAIL" "acceptance manifest is for another candidate or has an unknown schema"; return
    }
    $declared = New-Object System.Collections.Hashtable ([StringComparer]::Ordinal)
    foreach ($entry in $acceptance.reports) { $declared[$entry.row] = $entry }
    foreach ($row in ($RequiredRows + $OptionalRows)) {
        $label = "acceptance " + $row
        $optional = $OptionalRows -ccontains $row
        $prefix = ""
        if ($optional) { $prefix = "optional, does not block: " }
        if (-not $declared.ContainsKey($row)) { Add-Row $label "NOT RUN" ($prefix + "no report") $optional; continue }
        $entry = $declared[$row]
        if ($entry.file -cne ("acceptance-" + $row + ".json") -or -not $Listed.ContainsKey($entry.file) -or $Listed[$entry.file] -cne $entry.sha256) {
            Add-Row $label "FAIL" "report file is not the signed one"; continue
        }
        $report = Read-Json (Join-Path $Dir $entry.file)
        if (-not (Has-Property $report "candidate_commit") -or $report.candidate_commit -isnot [string] -or $report.candidate_commit -cne $Manifest.source.commit) { Add-Row $label "FAIL" "report is not for this commit"; continue }
        if (-not (Has-Property $report "candidate_image") -or $report.candidate_image -isnot [string] -or $report.candidate_image -cne $Manifest.image.index_digest) { Add-Row $label "FAIL" "report is not for this image index"; continue }
        if ($BlindRows -ccontains $row -and (-not (Has-Property $report "rehearsal") -or $report.rehearsal -isnot [bool] -or $report.rehearsal)) { Add-Row $label "FAIL" "rehearsal report: rehearsal must be JSON false"; continue }
        if ($BlindRows -ccontains $row -and (-not (Has-Property $report "version") -or $report.version -isnot [string] -or $report.version -cne $Manifest.version)) { Add-Row $label "FAIL" ("report does not name version " + $Manifest.version); continue }
        if ($row -ceq $UpgradeRow -and (-not (Has-Property $report "from_version") -or $report.from_version -isnot [string] -or $report.from_version -cne $UpgradeFromVersion -or -not (Has-Property $report "from_image") -or $report.from_image -isnot [string] -or $report.from_image -cne $UpgradeFromImage)) { Add-Row $label "FAIL" ("upgrade report does not start from NetOps " + $UpgradeFromVersion + " (" + $UpgradeFromImage + ")"); continue }
        $checks = @($report.checks)
        if ($checks.Count -eq 0) { Add-Row $label "FAIL" "report has no checks"; continue }
        $unknown = @($checks | Where-Object { $ReportStatuses -cnotcontains $_.status })
        $failed = @($checks | Where-Object { $_.status -ceq "FAIL" })
        $notRun = @($checks | Where-Object { $_.status -ceq "NOT RUN" })
        $required = @()
        if ($RequiredChecks.ContainsKey($row)) { $required = @($RequiredChecks[$row]) }
        $names = @($checks | Where-Object { (Has-Property $_ "check") -and $_.check -is [string] } | ForEach-Object { $_.check })
        $absent = @($required | Where-Object { $name = $_; @($names | Where-Object { $_ -ceq $name }).Count -ne 1 })
        if ($unknown.Count -gt 0) { Add-Row $label "FAIL" ("unknown status " + $unknown[0].status) }
        elseif ($failed.Count -gt 0) { Add-Row $label "FAIL" ([string]$failed.Count + " of " + $checks.Count + " checks failed: " + $failed[0].check) }
        elseif ($absent.Count -gt 0) { Add-Row $label "FAIL" ("required check missing or repeated: " + $absent[0]) }
        elseif ($BlindRows -ccontains $row -and $checks.Count -ne $required.Count) { Add-Row $label "FAIL" ("blind report must have exactly " + $required.Count + " checks") }
        elseif ($ProtocolRows -ccontains $row -and (-not (Has-Property $report "protocol_sha256") -or $report.protocol_sha256 -isnot [string] -or $report.protocol_sha256 -cnotmatch '^[0-9a-f]{64}\z')) { Add-Row $label "FAIL" "no protocol SHA-256 (protocol_sha256)" }
        elseif ($notRun.Count -gt 0) {
            $why = ""
            if ((Has-Property $notRun[0] "detail") -and $notRun[0].detail -is [string]) { $why = ": " + $notRun[0].detail }
            Add-Row $label "NOT RUN" ($prefix + [string]$notRun.Count + " of " + $checks.Count + " checks not run" + $why) $optional
        }
        else { Add-Row $label "PASS" ([string]$checks.Count + " checks") }
    }
}

$Snapshot = Join-Path ([IO.Path]::GetTempPath()) ("netops-sign-" + [guid]::NewGuid().ToString())
New-SnapshotDir $Snapshot
try {
    $OriginalDir = (Resolve-Path -LiteralPath $CandidateDir).Path
    if (-not (Test-CandidateDir $OriginalDir) -or -not (Copy-Snapshot $OriginalDir $Snapshot)) {
        $script:Rows | Format-Table Area, Status, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host
        Write-Host "OVERALL: FAIL"
        Write-Host "Signing refused: every row must be PASS."
        exit 1
    }
    $CandidateDir = $Snapshot
    $manifestFiles = @(Get-ChildItem -LiteralPath $CandidateDir -Filter "netops-*-manifest.json" -File | Where-Object { $_.Name -notlike "*-acceptance-manifest.json" })
    if ($manifestFiles.Count -ne 1) { Write-Host "Expected exactly one release manifest netops-X.Y.Z-manifest.json in the candidate directory."; exit 1 }
    $manifestPath = $manifestFiles[0].FullName
    $manifest = Read-Json $manifestPath
    if (-not (Has-Property $manifest "version") -or $manifest.version -isnot [string] -or $manifest.version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+\z') { Write-Host "The release manifest has no valid version."; exit 1 }
    $sumsPath = Join-Path $CandidateDir ("netops-" + $manifest.version + "-SHA256SUMS")
    if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) { Write-Host ("Missing " + $sumsPath); exit 1 }
    $listed = Read-Sums $CandidateDir $sumsPath
    if ($null -cne $listed -and (Test-Manifest $manifest $listed $manifestFiles[0].Name)) {
        Test-PinnedEnv $CandidateDir $manifest
        Test-Registry $manifest
        Test-Vulnerabilities $CandidateDir $manifest $listed
        Test-Acceptance $CandidateDir $manifest $listed
    }
    Test-ReleaseDocs $SourceDir $manifest.version

    $script:Rows | Format-Table Area, Status, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    $failed = @($script:Rows | Where-Object { $_.Status -ceq "FAIL" -or @("PASS", "NOT RUN") -cnotcontains $_.Status })
    $notRun = @($script:Rows | Where-Object { $_.Status -ceq "NOT RUN" -and -not $_.Optional })
    $overall = "PASS"
    if ($failed.Count -gt 0 -or $script:Rows.Count -eq 0) { $overall = "FAIL" } elseif ($notRun.Count -gt 0) { $overall = "NOT RUN" }
    Write-Host ("OVERALL: " + $overall + "   checksum list SHA-256 " + (Get-FileSha256 $sumsPath))
    if ($overall -ne "PASS") { Write-Host "Signing refused: every row must be PASS."; exit 1 }
    if ($CheckOnly) { exit 0 }

    $answer = Read-Host ("Sign " + (Split-Path -Leaf $sumsPath) + " with your GitHub identity now? Type SIGN to continue")
    if ($answer -cne "SIGN") { Write-Host "Not signed."; exit 1 }
    $bundle = $sumsPath + ".sigstore.json"
    $published = Join-Path $OriginalDir (Split-Path -Leaf $bundle)
    if (Test-Path -LiteralPath $bundle) { Write-Host ("Not signed: " + $published + " already exists. Remove it to sign again."); exit 1 }
    & $Cosign sign-blob --yes --fulcio-auth-flow=normal --bundle $bundle $sumsPath
    if ($LASTEXITCODE -ne 0) { Write-Host "cosign sign-blob failed."; exit 1 }
    & $Cosign verify-blob --bundle $bundle --certificate-identity $Identity --certificate-oidc-issuer $Issuer $sumsPath
    if ($LASTEXITCODE -ne 0) { Write-Host "Verification of the new signature failed."; exit 1 }
    $signedSums = Get-FileSha256 $sumsPath
    $originalSums = Join-Path $OriginalDir (Split-Path -Leaf $sumsPath)
    if (-not (Test-Path -LiteralPath $originalSums -PathType Leaf) -or (Get-FileSha256 $originalSums) -cne $signedSums) {
        Write-Host ("Signed the validated snapshot of " + (Split-Path -Leaf $sumsPath) + " (SHA-256 " + $signedSums + "), but " + $originalSums + " no longer matches it. The bundle was not copied to the candidate directory.")
        exit 1
    }
    if (Test-Path -LiteralPath $published) { Write-Host ("Not copied: " + $published + " already exists and was not overwritten."); exit 1 }
    $bundleBytes = [IO.File]::ReadAllBytes($bundle)
    Write-NewFile $published $bundleBytes
    if ((Get-FileSha256 $published) -cne (Get-Sha256Hex $bundleBytes)) { Write-Host ("Copy of the bundle differs from the signed one: " + $published); exit 1 }
    Write-Host ("Signed and verified the validated snapshot of " + (Split-Path -Leaf $sumsPath) + " (SHA-256 " + $signedSums + "). Bundle: " + $published + "  SHA-256 " + (Get-Sha256Hex $bundleBytes))
    exit 0
}
finally { Remove-Item -LiteralPath $Snapshot -Recurse -Force }
