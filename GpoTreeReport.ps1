<#
.SYNOPSIS
  Generates an HTML Group Policy Tree report by OU with per-GPO flags and settings, plus Unused GPOs.

.PARAMETER OutputPath
  Path to save the HTML file. Defaults to ".\GpoTreeReport.html".

.NOTES
  Requires RSAT modules: ActiveDirectory, GroupPolicy
  Run in a context that can read AD and GPOs.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\GpoTreeReport.html"
)

# ---------- Prereqs ----------
$modules = @("ActiveDirectory","GroupPolicy")
foreach ($m in $modules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Error "Required module '$m' is not available. Install/enable RSAT or import the module and re-run."
        return
    }
}
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

# ---------- Helpers ----------
function Get-DomainRootObject {
    try {
        $dn = (Get-ADDomain).DistinguishedName
        return Get-ADObject -Identity $dn -Properties gPLink,gPOptions,Name,DistinguishedName
    } catch {
        Write-Verbose "Could not retrieve domain root object: $_"
        return $null
    }
}

function Parse-gPLinkString {
    <#
      gPLink example:
        [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0][LDAP://cn={GUID2},...,DC=...;2]
      Options bitmask:
        1 = Link Disabled
        2 = Enforced (No Override)
    #>
    param([string]$gPLink)
    $links = @()
    if ([string]::IsNullOrWhiteSpace($gPLink)) { return $links }
    $matches = [regex]::Matches($gPLink, '\[(?<entry>.*?)\]')
    foreach ($m in $matches) {
        $entry = $m.Groups['entry'].Value
        $opt = 0
        if ($entry -match 'LDAP://[^;]+;(?<opt>\d+)$') { $opt = [int]$Matches['opt'] }
        $guid = $null
        if ($entry -match 'cn=\{(?<g>[0-9a-fA-F-]{36})\},cn=policies,cn=system') { $guid = $Matches['g'] }
        elseif ($entry -match '\{(?<g>[0-9a-fA-F-]{36})\}') { $guid = $Matches['g'] }
        if ($guid) {
            $links += [pscustomobject]@{
                Guid         = $guid
                Options      = $opt
                Enforced     = [bool]($opt -band 2)
                LinkDisabled = [bool]($opt -band 1)
            }
        }
    }
    return $links
}

function HtmlEsc([string]$s) {
    if ($null -eq $s) { return "" }
    return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function Get-GpoReportXmlByGuid([guid]$Guid) {
    try {
        $xmlText = Get-GPOReport -Guid $Guid -ReportType Xml -ErrorAction Stop
        return [xml]$xmlText
    } catch { return $null }
}

function Get-GpoWmiFilterFromXml([xml]$GpoXml) {
    if (-not $GpoXml) { return $null }
    $w = $GpoXml.GPO.WMIFilter
    if ($w -and $w.Name) {
        if ($w.Query) { return "{0} ({1})" -f $w.Name, ($w.Query -replace '\s+',' ') }
        return $w.Name
    }
    return $null
}

function Get-GpoSecurityFilters($GpoName) {
    # Trustees with Apply Group Policy = Allow
    $list = @()
    try {
        $perms = Get-GPPermission -Name $GpoName -All -ErrorAction Stop
        foreach ($p in $perms) {
            if ($p.Permission -eq 'GpoApply' -and $p.Type -eq 'Allow') {
                $list += $p.Trustee.Name
            }
        }
    } catch {}
    return ($list | Sort-Object -Unique)
}

function Get-GpoStatusInfo($gpoObj, [xml]$gpoXml) {
    $status = $null
    if ($gpoObj -and $gpoObj.PSObject.Properties.Name -contains 'GpoStatus') {
        $status = [string]$gpoObj.GpoStatus
    }
    if (-not $status -and $gpoXml -and $gpoXml.GPO.GpoStatus) {
        $status = [string]$gpoXml.GPO.GpoStatus
    }
    if (-not $status) { $status = "None" }

    $compDisabled = ($status -match 'Computer' -or $status -match 'All')
    $userDisabled = ($status -match 'User' -or $status -match 'All')

    [pscustomobject]@{
        StatusString         = $status
        ComputerSettingsDisabled = $compDisabled
        UserSettingsDisabled     = $userDisabled
    }
}

function Get-GpoSettingLines([xml]$GpoXml) {
    # Flatten to one-liners; covers common nodes, falls back gracefully
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $GpoXml) { return $lines }

    # Admin Templates-style <Policy> nodes (ExtensionData)
    $policyNodes = $GpoXml.SelectNodes("//ExtensionData/Extension/Policy")
    foreach ($n in $policyNodes) {
        $disp  = @($n.displayName, $n.Attributes['displayName'].Value | ? {$_})[0]
        $state = @($n.state, $n.Attributes['state'].Value | ? {$_})[0]
        $key   = @($n.key, $n.Attributes['key'].Value | ? {$_})[0]
        $val   = @($n.value, $n.Attributes['value'].Value | ? {$_})[0]
        $data  = @($n.data, $n.Attributes['data'].Value | ? {$_})[0]
        $parts = @(); if ($disp){$parts+=$disp}; if($state){$parts+="State=$state"}; if($key){$parts+="Key=$key"}; if($val){$parts+="ValueName=$val"}; if($data){$parts+="Data=$data"}
        if ($parts.Count) { $lines.Add(($parts -join " | ")) }
    }

    # Registry Preferences
    $regNodes = $GpoXml.SelectNodes("//RegistrySettings/RegistrySetting")
    foreach ($n in $regNodes) {
        $lines.Add(("RegistryPreference | Action={0} | Key={1} | ValueName={2} | Data={3} | Type={4}" -f $n.Action,$n.Key,$n.ValueName,$n.Data,$n.Type))
    }

    # Scripts (Startup/Shutdown/Logon/Logoff)
    $scriptNodes = $GpoXml.SelectNodes("//Scripts/*/Script")
    foreach ($s in $scriptNodes) {
        $phase = $s.ParentNode.Name; $cmd = $s.Command; $pars = $s.Parameters
        $lines.Add(("Script:{0} | {1} {2}" -f $phase,$cmd,$pars).Trim())
    }

    # Generic Policy nodes under Computer/User trees
    $secPolNodes = $GpoXml.SelectNodes("//Computer/*//Policy | //User/*//Policy")
    foreach ($n in $secPolNodes) {
        if ($policyNodes -and ($policyNodes -contains $n)) { continue } # avoid dupes
        $disp  = @($n.displayName, $n.Attributes['displayName'].Value | ? {$_})[0]
        $state = @($n.state, $n.Attributes['state'].Value | ? {$_})[0]
        $val   = @($n.value, $n.Attributes['value'].Value | ? {$_})[0]
        $data  = @($n.data, $n.Attributes['data'].Value | ? {$_})[0]
        $key   = @($n.key, $n.Attributes['key'].Value | ? {$_})[0]
        $parts = @(); if ($disp){$parts+=$disp}; if($state){$parts+="State=$state"}; if($key){$parts+="Key=$key"}; if($val){$parts+="ValueName=$val"}; if($data){$parts+="Data=$data"}
        if ($parts.Count) { $lines.Add(($parts -join " | ")) }
    }

    # Common summaries for Account/Kerberos/Audit
    foreach ($nodeName in @("Account","Kerberos","Audit")) {
        $nodes = $GpoXml.SelectNodes("//Computer/$nodeName/*")
        foreach ($n in $nodes) {
            if ($n.InnerText -and $n.InnerText.Trim()) {
                $lines.Add( ("Computer:{0} | {1}" -f $nodeName, ($n.OuterXml -replace '<.*?>',' ' -replace '\s+',' ').Trim()) )
            }
        }
    }

    # De-dup & clean
    ($lines | ? { $_ -and $_.Trim() } | Sort-Object -Unique)
}

# ---------- Collect data ----------
$domain = Get-ADDomain
$domainRoot = Get-DomainRootObject
$ous = Get-ADOrganizationalUnit -Filter * -Properties gPLink,gPOptions,Name,DistinguishedName | Sort-Object DistinguishedName
if ($domainRoot) { $ous = @($domainRoot) + $ous }

# All GPOs map by Guid (string)
$allGpos = @{}
(Get-GPO -All) | ForEach-Object { $allGpos[$_.Id.Guid.ToString()] = $_ }

# Caches
$gpoXmlCache      = @{}
$gpoWmiCache      = @{}
$gpoFiltersCache  = @{}
$gpoSettingsCache = @{}
$gpoStatusCache   = @{}

# Pre-warm caches for all GPOs (keeps linked/unlinked path uniform)
foreach ($kv in $allGpos.GetEnumerator()) {
    $guidStr = $kv.Key
    $gpo     = $kv.Value
    $xml     = Get-GpoReportXmlByGuid -Guid $gpo.Id
    $gpoXmlCache[$guidStr] = $xml
    $gpoWmiCache[$guidStr] = Get-GpoWmiFilterFromXml -GpoXml $xml
    $gpoFiltersCache[$guidStr] = Get-GpoSecurityFilters -GpoName $gpo.DisplayName
    $gpoSettingsCache[$guidStr] = Get-GpoSettingLines -GpoXml $xml
    $gpoStatusCache[$guidStr] = Get-GpoStatusInfo -gpoObj $gpo -gpoXml $xml
}

# Track linked GPO Guids
$linkedGuids = [System.Collections.Generic.HashSet[string]]::new()

# ---------- Build HTML ----------
$sb = New-Object System.Text.StringBuilder

$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; }
h1 { margin-bottom: 0; }
.subtle { color: #555; }
.kv { font-family: ui-monospace, Consolas, monospace; }
.badge { display:inline-block; padding:2px 6px; border-radius:8px; font-size:12px; margin-right:6px; border:1px solid #ccc; }
.badge.enforced { background:#ffe9e9; border-color:#e09999; }
.badge.disabled { background:#f5f5f5; }
.badge.ok { background:#eaf7ea; border-color:#88b188; }
.badge.warn { background:#fff7e0; border-color:#d9c06b; }
.tree { margin: 0; padding-left: 20px; list-style-type: none; }
.tree li { margin: 6px 0; }
.tree li .title { font-weight:600; }
details { margin: 4px 0; }
summary { cursor: pointer; }
.small { font-size: 12px; color:#666; }
.meta { margin:2px 0 6px 0; }
code { background:#f6f6f6; padding:1px 4px; border-radius:4px; }
.section { margin-top: 24px; }
hr { border:0; border-top:1px solid #ddd; margin:16px 0; }
table { border-collapse: collapse; }
td, th { padding: 6px 8px; border:1px solid #ddd; }
</style>
"@

$now = Get-Date
$header = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>GPO Tree Report - $($domain.DNSRoot)</title>
$css
</head>
<body>
<h1>GPO Tree Report</h1>
<div class="subtle">Domain: <span class="kv">$(HtmlEsc $domain.DNSRoot)</span> &bull; Generated: <span class="kv">$($now.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
<hr />
"@

$null = $sb.Append($header)

# Summary (counts + efficiency list)
$totalOus = ($ous | Measure-Object).Count
$totalGpos = ($allGpos.Count)
$unusedGuids = [System.Collections.Generic.HashSet[string]]::new()
foreach ($k in $allGpos.Keys) { $unusedGuids.Add($k) | Out-Null }

# We'll fill linkedGuids while rendering OU tree
# Build OU Tree
$null = $sb.Append('<div class="section"><h2>OU → GPO Links</h2><ul class="tree">')

foreach ($ou in $ous) {
    $ouName = if ($ou -eq $domainRoot) { "Domain (root)" } else { $ou.Name }
    $dn = $ou.DistinguishedName
    $inheritanceBlocked = $false
    if ($ou.PSObject.Properties.Name -contains 'gPOptions') {
        $inheritanceBlocked = [bool]($ou.gPOptions -band 1)
    }

    $null = $sb.AppendFormat('<li><span class="title">OU:</span> {0} <span class="small kv">({1})</span> {2}',
        (HtmlEsc $ouName),
        (HtmlEsc $dn),
        ($(if($inheritanceBlocked){'<span class="badge warn">Inheritance Blocked</span>'} else {''}))
    )

    $links = Parse-gPLinkString -gPLink $ou.gPLink

    if (-not $links -or $links.Count -eq 0) {
        $null = $sb.Append('<div class="small subtle">(No linked GPOs)</div></li>')
        continue
    }

    $null = $sb.Append('<ul class="tree">')

    foreach ($l in $links) {
        $linkedGuids.Add($l.Guid) | Out-Null
        $unusedGuids.Remove($l.Guid) | Out-Null

        $gpo = $allGpos[$l.Guid]
        if (-not $gpo) {
            $null = $sb.AppendFormat('<li><span class="title">Missing GPO:</span> {0}</li>', (HtmlEsc $l.Guid))
            continue
        }

        $guidStr = $gpo.Id.Guid.ToString()
        $xml     = $gpoXmlCache[$guidStr]
        $wmi     = $gpoWmiCache[$guidStr]
        $filters = $gpoFiltersCache[$guidStr]
        $settings= $gpoSettingsCache[$guidStr]
        $status  = $gpoStatusCache[$guidStr]

        $badges = @()
        if ($l.Enforced)     { $badges += '<span class="badge enforced">Enforced</span>' }
        if ($l.LinkDisabled) { $badges += '<span class="badge disabled">Link Disabled</span>' }
        if ($status.UserSettingsDisabled)     { $badges += '<span class="badge warn">User settings disabled</span>' }
        if ($status.ComputerSettingsDisabled) { $badges += '<span class="badge warn">Computer settings disabled</span>' }

        $null = $sb.Append('<li>')
        $null = $sb.AppendFormat('<div><span class="title">GPO:</span> {0} <span class="small kv">({1})</span> {2}',
            (HtmlEsc $gpo.DisplayName),
            (HtmlEsc $guidStr),
            ($badges -join ' ')
        )

        if ($wmi) { $null = $sb.AppendFormat(' <span class="badge ok">WMI: {0}</span>', (HtmlEsc $wmi)) }

        $null = $sb.Append('</div>')

        # Meta row: Security filters & status
        $null = $sb.Append('<div class="meta small">')
        $null = $sb.AppendFormat('<b>Link Flags:</b> Enforced={0}, LinkEnabled={1} &nbsp;&nbsp; | &nbsp;&nbsp; ',
            $(if($l.Enforced){'True'}else{'False'}),
            $(if($l.LinkDisabled){'False'}else{'True'})
        )
        $null = $sb.AppendFormat('<b>GPO Status:</b> {0}',
            (HtmlEsc $status.StatusString)
        )
        if ($filters -and $filters.Count) {
            $null = $sb.Append(' &nbsp;&nbsp; | &nbsp;&nbsp; <b>Security Filtering:</b> ')
            $null = $sb.Append( ($filters | ForEach-Object { HtmlEsc $_ }) -join ', ' )
        }
        $null = $sb.Append('</div>')

        # Settings block (collapsible)
        $null = $sb.AppendFormat('<details><summary>Settings ({0})</summary><ul class="tree">', $settings.Count)
        if ($settings.Count -gt 0) {
            foreach ($s in $settings) {
                $null = $sb.AppendFormat('<li><code>{0}</code></li>', (HtmlEsc $s))
            }
        } else {
            $null = $sb.Append('<li class="small subtle">(No explicit settings parsed or not applicable)</li>')
        }
        $null = $sb.Append('</ul></details>')

        $null = $sb.Append('</li>')
    }

    $null = $sb.Append('</ul></li>')
}

$null = $sb.Append('</ul></div>')  # end OU → GPO Links section

# Efficiency quick list (GPOs with disabled halves)
$gposUserDisabled = @()
$gposComputerDisabled = @()
foreach ($kv in $gpoStatusCache.GetEnumerator()) {
    $guid = $kv.Key
    $gpo  = $allGpos[$guid]
    if (-not $gpo) { continue }
    if ($kv.Value.UserSettingsDisabled)     { $gposUserDisabled     += $gpo }
    if ($kv.Value.ComputerSettingsDisabled) { $gposComputerDisabled += $gpo }
}

# Summary header
$null = $sb.Append('<div class="section"><h2>Summary</h2>')
$null = $sb.Append('<table><tbody>')
$null = $sb.AppendFormat('<tr><th>Total OUs</th><td>{0}</td></tr>', $totalOus)
$null = $sb.AppendFormat('<tr><th>Total GPOs</th><td>{0}</td></tr>', $totalGpos)
$null = $sb.AppendFormat('<tr><th>Linked GPOs</th><td>{0}</td></tr>', $linkedGuids.Count)
$null = $sb.AppendFormat('<tr><th>Unused GPOs</th><td>{0}</td></tr>', $unusedGuids.Count)
$null = $sb.Append('</tbody></table>')

# Efficiency lists
$null = $sb.Append('<div style="margin-top:10px">')
$null = $sb.Append('<details><summary><b>GPOs with User settings disabled</b> (for efficiency)</summary><ul class="tree">')
if ($gposUserDisabled) {
    foreach ($g in ($gposUserDisabled | Sort-Object DisplayName)) {
        $null = $sb.AppendFormat('<li>{0} <span class="small kv">({1})</span></li>', (HtmlEsc $g.DisplayName), (HtmlEsc $g.Id.Guid.ToString()))
    }
} else {
    $null = $sb.Append('<li class="small subtle">(None)</li>')
}
$null = $sb.Append('</ul></details>')

$null = $sb.Append('<details><summary><b>GPOs with Computer settings disabled</b> (for efficiency)</summary><ul class="tree">')
if ($gposComputerDisabled) {
    foreach ($g in ($gposComputerDisabled | Sort-Object DisplayName)) {
        $null = $sb.AppendFormat('<li>{0} <span class="small kv">({1})</span></li>', (HtmlEsc $g.DisplayName), (HtmlEsc $g.Id.Guid.ToString()))
    }
} else {
    $null = $sb.Append('<li class="small subtle">(None)</li>')
}
$null = $sb.Append('</ul></details>')
$null = $sb.Append('</div></div>')

# Unused GPOs section
$null = $sb.Append('<div class="section"><h2>Unused GPOs</h2>')
if ($unusedGuids.Count -eq 0) {
    $null = $sb.Append('<div class="small subtle">(None)</div>')
} else {
    $null = $sb.Append('<ul class="tree">')
    foreach ($guid in ($unusedGuids | Sort-Object)) {
        $g = $allGpos[$guid]
        if (-not $g) { continue }
        $xml     = $gpoXmlCache[$guid]
        $wmi     = $gpoWmiCache[$guid]
        $filters = $gpoFiltersCache[$guid]
        $settings= $gpoSettingsCache[$guid]
        $status  = $gpoStatusCache[$guid]
        $badges = @()
        if ($status.UserSettingsDisabled)     { $badges += '<span class="badge warn">User settings disabled</span>' }
        if ($status.ComputerSettingsDisabled) { $badges += '<span class="badge warn">Computer settings disabled</span>' }

        $null = $sb.Append('<li>')
        $null = $sb.AppendFormat('<div><span class="title">GPO:</span> {0} <span class="small kv">({1})</span> {2}',
            (HtmlEsc $g.DisplayName),
            (HtmlEsc $g.Id.Guid.ToString()),
            ($badges -join ' ')
        )
        if ($wmi) { $null = $sb.AppendFormat(' <span class="badge ok">WMI: {0}</span>', (HtmlEsc $wmi)) }
        $null = $sb.Append('</div>')

        if ($filters -and $filters.Count) {
            $null = $sb.Append('<div class="meta small"><b>Security Filtering:</b> ')
            $null = $sb.Append( ($filters | ForEach-Object { HtmlEsc $_ }) -join ', ' )
            $null = $sb.Append('</div>')
        }

        $null = $sb.AppendFormat('<details><summary>Settings ({0})</summary><ul class="tree">', $settings.Count)
        if ($settings.Count -gt 0) {
            foreach ($s in $settings) {
                $null = $sb.AppendFormat('<li><code>{0}</code></li>', (HtmlEsc $s))
            }
        } else {
            $null = $sb.Append('<li class="small subtle">(No explicit settings parsed or not applicable)</li>')
        }
        $null = $sb.Append('</ul></details>')

        $null = $sb.Append('</li>')
    }
    $null = $sb.Append('</ul>')
}
$null = $sb.Append('</div>')

# Footer
$null = $sb.Append('<hr /><div class="small subtle">Tip: A GPO with one half disabled (User/Computer) can process faster when the other half is not needed.</div>')
$null = $sb.Append('</body></html>')

# Write output
try {
    $html = $sb.ToString()
    $dir = Split-Path -Path $OutputPath -Parent
    if ($dir -and -not (Test-Path -Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    Write-Host "Report written to: $OutputPath"
} catch {
    Write-Error "Failed to write HTML report: $_"
}
