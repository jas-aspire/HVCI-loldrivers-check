# ============================================================
# Local HVCI / LOLDrivers Comparison
#
# Windows PowerShell 5.1+
#
# Downloads:
#   - LOLDrivers database from loldrivers.io API
#   - Microsoft VulnerableDriverBlockList.zip (extracts XML)
#
# Only compares Category = "vulnerable driver" entries.
# ============================================================

$ErrorActionPreference = "Stop"

$loldriversUrl    = "https://www.loldrivers.io/api/drivers.json"
$blocklistZipUrl  = "https://download.microsoft.com/download/75bf7aa6-7700-43cc-bbac-9dfc0cc4ed50/VulnerableDriverBlockList.zip"
$zipPath          = (Join-Path $env:TEMP "VulnerableDriverBlockList.zip")
$zipExtractPath   = (Join-Path $env:TEMP "VulnerableDriverBlockList")
$blocklistXmlPath = (Join-Path $zipExtractPath "DriverPolicy_Enforced.xml")
$resultsPath      = (Join-Path $env:TEMP "lol_drivers_policy_results.json")

Write-Host "=============================================="
Write-Host " Local HVCI / LOLDrivers Comparison"
Write-Host "=============================================="
Write-Host ""

# ------------------------------------------------------------------
# Hash helpers
# ------------------------------------------------------------------

function Normalize-Hash([string]$h) {
    return $h.Trim().ToUpperInvariant() -replace '[-: ]',''
}

function Add-Hash([hashtable]$tbl, [object]$val) {
    if ($null -eq $val) { return }
    $s = [string]$val
    if ([string]::IsNullOrWhiteSpace($s)) { return }
    $n = Normalize-Hash $s
    if ($n -match '^[0-9A-F]+$') { $tbl[$n] = $true }
}

function DictGet([object]$d, [string]$key) {
    if ($d -is [System.Collections.IDictionary] -and $d.ContainsKey($key)) {
        return $d[$key]
    }
    return $null
}

# ------------------------------------------------------------------
# 1. Download LOLDrivers JSON
# ------------------------------------------------------------------

Write-Host "[1/4] Downloading LOLDrivers database..."
Write-Host ("      Source: {0}" -f $loldriversUrl)

try {
    $lolJson = (Invoke-WebRequest -Uri $loldriversUrl -UseBasicParsing -ErrorAction Stop).Content
} catch {
    throw ("Failed to download LOLDrivers JSON: {0}" -f $_.Exception.Message)
}

Add-Type -AssemblyName System.Web.Extensions
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$ser.MaxJsonLength = [Int32]::MaxValue

$allDrivers = @($ser.DeserializeObject($lolJson))

# Filter: only "vulnerable driver", skip "malicious" etc.
$drivers = @($allDrivers | Where-Object {
    $cat = [string](DictGet $_ "Category")
    $cat -ieq "vulnerable driver"
})

Write-Host ("      Total entries   : {0:N0}" -f $allDrivers.Count)
Write-Host ("      Vulnerable only : {0:N0}" -f $drivers.Count)
Write-Host ("      Skipped         : {0:N0}" -f ($allDrivers.Count - $drivers.Count))
Write-Host ""

# ------------------------------------------------------------------
# 2. Download & extract Microsoft VulnerableDriverBlockList
# ------------------------------------------------------------------

Write-Host "[2/4] Downloading VulnerableDriverBlockList..."
Write-Host ("      Source: {0}" -f $blocklistZipUrl)

try {
    Invoke-WebRequest `
        -Uri $blocklistZipUrl `
        -OutFile $zipPath `
        -UseBasicParsing `
        -ErrorAction Stop
} catch {
    throw ("Failed to download blocklist zip: {0}" -f $_.Exception.Message)
}

Write-Host ("      Downloaded: {0:N0} bytes" -f (Get-Item $zipPath).Length)

# Clear previous extract if any
if (Test-Path $zipExtractPath) {
    Remove-Item $zipExtractPath -Recurse -Force
}

Write-Host "      Extracting zip..."

try {
    Expand-Archive -LiteralPath $zipPath -DestinationPath $zipExtractPath -Force -ErrorAction Stop
} catch {
    throw ("Failed to extract blocklist zip: {0}" -f $_.Exception.Message)
}

# Find DriverPolicy_Enforced.xml anywhere in the extract
$xmlFile = Get-ChildItem -Path $zipExtractPath -Filter "DriverPolicy_Enforced.xml" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $xmlFile) {
    Write-Host ""
    Write-Host "Files extracted:"
    Get-ChildItem $zipExtractPath -Recurse | ForEach-Object { Write-Host ("  {0}" -f $_.FullName) }
    throw "DriverPolicy_Enforced.xml not found in extracted zip."
}

$blocklistXmlPath = $xmlFile.FullName
Write-Host ("      Using XML: {0}" -f $blocklistXmlPath)
Write-Host ""

# ------------------------------------------------------------------
# 3. Parse XML blocklist
# ------------------------------------------------------------------

Write-Host "[3/4] Parsing VulnerableDriverBlockList XML..."

[xml]$policy = Get-Content $blocklistXmlPath -Raw

$nsUri = $policy.DocumentElement.NamespaceURI
if ([string]::IsNullOrWhiteSpace($nsUri)) { $nsUri = "urn:schemas-microsoft-com:sipolicy" }
$ns = New-Object System.Xml.XmlNamespaceManager($policy.NameTable)
$ns.AddNamespace("si", $nsUri)

$policyVer  = $policy.SelectSingleNode("/si:SiPolicy/@VersionEx", $ns)
$policyId   = $policy.SelectSingleNode("/si:SiPolicy/@PolicyID",  $ns)
$policyName = $policy.SelectSingleNode("/si:SiPolicy/@Name",       $ns)

if ($policyVer)  { Write-Host ("      VersionEx : {0}" -f $policyVer.Value) }
if ($policyId)   { Write-Host ("      PolicyID  : {0}" -f $policyId.Value) }
if ($policyName) { Write-Host ("      Name      : {0}" -f $policyName.Value) }
Write-Host ""

$frNode = $policy.SelectSingleNode("//si:FileRules", $ns)
$frList = @()
if ($frNode) {
    $frList = @($frNode.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
}

$denyHashes    = @{}
$denyFileRules = New-Object System.Collections.Generic.List[object]

foreach ($r in $frList) {
    if ($r.LocalName -ne "Deny") { continue }
    $h = $r.GetAttribute("Hash")
    if (-not [string]::IsNullOrWhiteSpace($h)) { $denyHashes[(Normalize-Hash $h)] = $r }
    $fn = $r.GetAttribute("FileName")
    if (-not [string]::IsNullOrWhiteSpace($fn)) {
        [void]$denyFileRules.Add([PSCustomObject]@{
            FileName = $fn
            MaxVer   = $r.GetAttribute("MaximumFileVersion")
            ID       = $r.GetAttribute("ID")
        })
    }
}

Write-Host ("      Deny hash rules     : {0:N0}" -f $denyHashes.Count)
Write-Host ("      Deny filename rules : {0:N0}" -f $denyFileRules.Count)
Write-Host ""

# ------------------------------------------------------------------
# 4. Compare
# ------------------------------------------------------------------

Write-Host "[4/4] Comparing LOLDrivers against blocklist..."
Write-Host ""

$blocked    = New-Object System.Collections.Generic.List[object]
$notMatched = New-Object System.Collections.Generic.List[object]

foreach ($entry in $drivers) {

    # Driver name from Tags array (contains the .sys filename)
    $tags = DictGet $entry "Tags"
    $driverTag = if ($tags -ne $null -and @($tags).Count -gt 0) { [string](@($tags)[0]) } else { "" }

    $samples = @(DictGet $entry "KnownVulnerableSamples")

    $desc = ""
    if ($samples.Count -gt 0) { $desc = [string](DictGet $samples[0] "Description") }

    $displayName = if (-not [string]::IsNullOrWhiteSpace($driverTag)) { $driverTag }
                   elseif (-not [string]::IsNullOrWhiteSpace($desc))  { $desc }
                   else { "<unnamed>" }

    # Collect all hashes across all samples + Authentihash sub-dicts
    $allHashes    = @{}
    $allFilenames = New-Object System.Collections.Generic.List[string]

    foreach ($s in $samples) {
        if ($null -eq $s) { continue }

        Add-Hash $allHashes (DictGet $s "MD5")
        Add-Hash $allHashes (DictGet $s "SHA1")
        Add-Hash $allHashes (DictGet $s "SHA256")

        $ah = DictGet $s "Authentihash"
        if ($ah -ne $null) {
            Add-Hash $allHashes (DictGet $ah "MD5")
            Add-Hash $allHashes (DictGet $ah "SHA1")
            Add-Hash $allHashes (DictGet $ah "SHA256")
        }

        $fn  = [string](DictGet $s "Filename")
        $ofn = [string](DictGet $s "OriginalFilename")
        if (-not [string]::IsNullOrWhiteSpace($fn))  { [void]$allFilenames.Add($fn) }
        if (-not [string]::IsNullOrWhiteSpace($ofn)) { [void]$allFilenames.Add($ofn) }
    }

    # Hash match
    $matchedRule = $null
    $matchedHash = $null
    $matchType   = $null

    foreach ($h in $allHashes.Keys) {
        if ($denyHashes.ContainsKey($h)) {
            $matchedRule = $denyHashes[$h]
            $matchedHash = $h
            $matchType   = "Hash"
            break
        }
    }

    # Filename match
    if (-not $matchedRule) {
        foreach ($fn in $allFilenames) {
            foreach ($rule in $denyFileRules) {
                if ($fn -ieq $rule.FileName) {
                    $matchedRule = $rule
                    $matchType   = "FileName"
                    break
                }
            }
            if ($matchedRule) { break }
        }
    }

    $ruleId = $null
    if ($matchedRule) {
        if ($matchedRule.PSObject.Properties["ID"]) { $ruleId = [string]$matchedRule.ID }
        elseif ($matchedRule.Attributes) {
            $ia = $matchedRule.Attributes["ID"]
            if ($ia) { $ruleId = [string]$ia.Value }
        }
    }

    $result = New-Object PSObject -Property ([ordered]@{
        Name        = $displayName
        Tag         = $driverTag
        Samples     = $samples.Count
        Matched     = [bool]$matchedRule
        MatchType   = $matchType
        MatchedHash = $matchedHash
        RuleID      = $ruleId
    })

    if ($matchedRule) { [void]$blocked.Add($result) }
    else              { [void]$notMatched.Add($result) }
}

# ------------------------------------------------------------------
# Results
# ------------------------------------------------------------------

Write-Host "=============================================="
Write-Host " RESULTS"
Write-Host "=============================================="
Write-Host ""
Write-Host ("Total vulnerable LOLDrivers:   {0:N0}" -f $drivers.Count)
Write-Host ("Matched by MS deny rules:      {0:N0}" -f $blocked.Count)
Write-Host ("NOT in blocklist (gap):        {0:N0}" -f $notMatched.Count)
Write-Host ""

Write-Host "Blocked / matched drivers:"
Write-Host "----------------------------------------------"
if ($blocked.Count -eq 0) {
    Write-Host "  None"
} else {
    foreach ($item in $blocked) {
        Write-Host ("  {0}" -f $item.Name)
        if ($item.MatchType)   { Write-Host ("      Match : {0}" -f $item.MatchType) }
        if ($item.MatchedHash) { Write-Host ("      Hash  : {0}" -f $item.MatchedHash) }
        if (-not [string]::IsNullOrWhiteSpace($item.RuleID)) { Write-Host ("      Rule  : {0}" -f $item.RuleID) }
        Write-Host ""
    }
}

Write-Host ""
Write-Host "Vulnerable drivers NOT in MS blocklist:"
Write-Host "----------------------------------------------"
if ($notMatched.Count -eq 0) {
    Write-Host "  None"
} else {
    foreach ($item in $notMatched) { Write-Host ("  {0}" -f $item.Name) }
}

# ------------------------------------------------------------------
# Save JSON
# ------------------------------------------------------------------

try {
    New-Object PSObject -Property ([ordered]@{
        Source_LOLDrivers    = $loldriversUrl
        Source_Blocklist     = $blocklistZipUrl
        BlocklistXml         = $blocklistXmlPath
        TotalLOLDrivers      = $allDrivers.Count
        VulnerableOnly       = $drivers.Count
        Matched              = $blocked.Count
        NotMatched           = $notMatched.Count
        MatchedDrivers       = $blocked.ToArray()
        NotMatchedDrivers    = $notMatched.ToArray()
    }) | ConvertTo-Json -Depth 10 | Set-Content $resultsPath -Encoding UTF8

    Write-Host ""
    Write-Host "Results JSON:"
    Write-Host ("  {0}" -f $resultsPath)
} catch {
    Write-Host ("WARNING: Could not save JSON: {0}" -f $_.Exception.Message)
}

Write-Host ""
Write-Host "=============================================="
Write-Host " Done"
Write-Host "=============================================="
