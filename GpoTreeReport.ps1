<# 
GPO Tree → HTML report (safe quoting; broad settings enumeration)
- OUs (incl. Domain root) → linked GPOs
- Flags: Enforced, Link Enabled/Disabled
- GPO Status badges: User/Computer settings disabled
- WMI filter, Security filtering groups
- One-line-per-setting from GPO XML (aggressive XPath, Admin Templates, Preferences, Scripts, SecEdit)
- Separate "Unused GPOs" section

Requirements: RSAT ActiveDirectory + GroupPolicy modules
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\GpoTreeReport.html"
)

# ---------- Prereqs ----------
$modules = @("ActiveDirectory","GroupPolicy")
foreach ($m in $modules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Error "Required module '$m' is not available. Install/enable RSAT and re-run."
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
    } catch { return $null }
}

function Parse-gPLinkString {
    param([string]$gPLink)
    $links = @()
    if ([string]::IsNullOrWhiteSpace($gPLink)) { return $links }
    $matches = [regex]::Matches($gPLink, '\[(?<entry>.*?)\]')
    foreach ($m in $matches) {
        $entry = $m.Groups['entry'].Value
        $opt = 0
        if ($entry -match 'LDAP://[^;]+;(?<opt>\d+)$') { $opt = [int]$Matches['opt'] }
        $guid = $null
        if     ($entry -match 'cn=\{(?<g>[0-9a-fA-F-]{36})\},cn=policies,cn=system') { $guid = $Matches['g'] }
        elseif ($entry -match '\{(?<g>[0-9a-fA-F-]{36})\}')                           { $guid = $Matches['g'] }
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
    try { [xml](Get-GPOReport -Guid $Guid -ReportType Xml -ErrorAction Stop) } catch { $null }
}

function Get-GpoWmiFilterFromXml([xml]$GpoXml) {
    if (-not $GpoXml) { return $null }
    $w = $GpoXml.GPO.WMIFilter
    if ($w -and $w.Name) {
        if ($w.Query) { return ("{0} ({1})" -f $w.Name, ($w.Query -replace '\s+',' ')) }
        return $w.Name
    }
    $null
}

function Get-GpoSecurityFilters($GpoName) {
    $list = @()
    try {
        $perms = Get-GPPermission -Name $GpoName -All -ErrorAction Stop
        foreach ($p in $perms) {
            if ($p.Permission -eq 'GpoApply' -and $p.Type -eq 'Allow') {
                $list += $p.Trustee.Name
            }
        }
    } catch {}
    $list | Sort-Object -Unique
}

function Get-GpoStatusInfo($gpoObj, [xml]$gpoXml) {
    $status = $null
    if ($gpoObj -and $gpoObj.PSObject.Properties.Name -contains 'GpoStatus') { $status = [string]$gpoObj.GpoStatus }
    if (-not $status -and $gpoXml -and $gpoXml.GPO.GpoStatus) { $status = [string]$gpoXml.GPO.GpoStatus }
    if (-not $status) { $status = "AllSettingsEnabled" }

    $compDisabled = $false; $userDisabled = $false
    switch ($status) {
        'AllSettingsDisabled'      { $compDisabled = $true; $userDisabled = $true }
        'ComputerSettingsDisabled' { $compDisabled = $true }
        'UserSettingsDisabled'     { $userDisabled = $true }
        default { }
    }

    [pscustomobject]@{
        StatusString              = $status
        ComputerSettingsDisabled  = $compDisabled
        UserSettingsDisabled      = $userDisabled
    }
}

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# UPDATED: Aggressive settings extraction over multiple schemas
function Get-GpoSettingLines([xml]$GpoXml) {
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $GpoXml) { return $lines }

    function Get-SideTag([xml.xmlelement]$node) {
        $n = $node
        while ($n -and $n.Name -ne "GPO") {
            if ($n.Name -eq "Computer") { return "[Computer]" }
            if ($n.Name -eq "User")     { return "[User]" }
            $n = $n.ParentNode
        }
        return ""
    }

    function Grab([xml.xmlelement]$node, [string]$side) {
        # Prefer attributes, then child elements
        $disp  = $node.GetAttribute("displayName")
        if (-not $disp) { $disp = $node.GetAttribute("name") }
        if (-not $disp -and $node.SelectSingleNode("displayName")) { $disp = $node.SelectSingleNode("displayName").InnerText }

        $state = $node.GetAttribute("state")
        if (-not $state) {
            $enabledAttr  = $node.GetAttribute("enabled")
            $disabledAttr = $node.GetAttribute("disabled")
            if ($enabledAttr)       { $state = "Enabled=$enabledAttr" }
            elseif ($disabledAttr)  { $state = "Disabled=$disabledAttr" }
            elseif ($node.SelectSingleNode("state")) { $state = $node.SelectSingleNode("state").InnerText }
        }

        $key   = $node.GetAttribute("key");        if (-not $key   -and $node.SelectSingleNode("key"))   { $key   = $node.SelectSingleNode("key").InnerText }
        $value = $node.GetAttribute("value");      if (-not $value -and $node.SelectSingleNode("value")) { $value = $node.SelectSingleNode("value").InnerText }
        $data  = $node.GetAttribute("data");       if (-not $data  -and $node.SelectSingleNode("data"))  { $data  = $node.SelectSingleNode("data").InnerText }

        $parts = @()
        if ($side)  { $parts += $side }
        if ($disp)  { $parts += $disp }
        if ($state) { $parts += "State=$state" }
        if ($key)   { $parts += "Key=$key" }
        if ($value) { $parts += "ValueName=$value" }
        if ($data)  { $parts += "Data=$data" }

        if (-not $disp -and -not $state -and -not $key -and -not $value -and -not $data) {
            $text = ($node.InnerText -replace '\s+',' ').Trim()
            if ($text) { $parts += $text }
        }
        if ($parts.Count) { $lines.Add(($parts -join " | ")) }
    }

    # 1) Any <Policy> element anywhere
    $policyNodes = $GpoXml.SelectNodes("//GPO//*[local-name()='Policy']")
    foreach ($n in $policyNodes) { Grab -node $n -side (Get-SideTag $n) }

    # 2) Registry Preferences (explicit)
    $regNodes = $GpoXml.SelectNodes("//GPO//RegistrySettings/RegistrySetting")
    foreach ($n in $regNodes) {
        $side = Get-SideTag $n
        $lines.Add(("{0} RegistryPreference | Action={1} | Key={2} | ValueName={3} | Data={4} | Type={5}" -f $side,$n.Action,$n.Key,$n.ValueName,$n.Data,$n.Type).Trim())
    }

    # 3) Generic Preferences catch-all (Files/Shortcuts/Tasks/etc.) — nodes with an 'action' attribute
    $prefNodes = $GpoXml.SelectNodes("//GPO//*[local-name()='Preferences']//*[@action]")
    foreach ($n in $prefNodes) {
        $side   = Get-SideTag $n
        $type   = $n.Name
        $action = $n.GetAttribute("action")
        $name   = $n.GetAttribute("name")
        $path   = $n.GetAttribute("path"); if (-not $path) { $path = $n.GetAttribute("targetPath") }
        $dest   = $n.GetAttribute("destination"); if (-not $path) { $path = $dest }
        $desc   = $n.GetAttribute("description")

        $parts = @($side, "Preference:$type", "Action=$action")
        if ($name) { $parts += "Name=$name" }
        if ($path) { $parts += "Path=$path" }
        if ($desc) { $parts += "Desc=$desc" }
        $lines.Add(($parts -join " | "))
    }

    # 4) Scripts (Startup/Shutdown/Logon/Logoff)
    $scriptNodes = $GpoXml.SelectNodes("//GPO//Scripts/*/Script")
    foreach ($s in $scriptNodes) {
        $phase = $s.ParentNode.Name
        $cmd   = $s.Command
        $pars  = $s.Parameters
        $side  = Get-SideTag $s
        $lines.Add(("{0} Script:{1} | {2} {3}" -f $side,$phase,$cmd,$pars).Trim())
    }

    # 5) Common SecEdit summaries (Account/Kerberos/Audit/etc.)
    foreach ($nodeName in @("Account","Kerberos","Audit","EventAudit","PasswordPolicy","KerberosPolicy")) {
        $nodes = $GpoXml.SelectNodes("//GPO//Computer/$nodeName/*")
        foreach ($n in $nodes) {
            $txt = ($n.OuterXml -replace '<.*?>',' ' -replace '\s+',' ').Trim()
            if ($txt) { $lines.Add(("[Computer] {0} | {1}" -f $nodeName, $txt)) }
        }
    }

    ($lines | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique)
}
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

function AddLine([System.Text.StringBuilder]$sb, [string]$text) { [void]$sb.Append($text) }

# ---------- Collect data ----------
$domain     = Get-ADDomain
$domainRoot = Get-DomainRootObject
$ous        = Get-ADOrganizationalUnit -Filter * -Properties gPLink,gPOptions,Name,DistinguishedName | Sort-Object DistinguishedName
if ($domainRoot) { $ous = @($domainRoot) + $ous }

# All GPOs
$allGpos = @{}
(Get-GPO -All) | ForEach-Object { $allGpos[$_.Id.Guid.ToString()] = $_ }

# Caches
$gpoXmlCache      = @{}
$gpoWmiCache      = @{}
$gpoFiltersCache  = @{}
$gpoSettingsCache = @{}
$gpoStatusCache   = @{}

foreach ($kv in $allGpos.GetEnumerator()) {
    $guidStr = $kv.Key
    $gpo     = $kv.Value
    $xml     = Get-GpoReportXmlByGuid -Guid $gpo.Id
    $gpoXmlCache[$guidStr]      = $xml
    $gpoWmiCache[$guidStr]      = Get-GpoWmiFilterFromXml -GpoXml $xml
    $gpoFiltersCache[$guidStr]  = Get-GpoSecurityFilters -GpoName $gpo.DisplayName
    $gpoSettingsCache[$guidStr] = Get-GpoSettingLines -GpoXml $xml
    $gpoStatusCache[$guidStr]   = Get-GpoStatusInfo -gpoObj $gpo -gpoXml $xml
}

# Linked/Unused tracking
$linkedGuids = [System.Collections.Generic.HashSet[string]]::new()
$unusedGuids = [System.Collections.Generic.HashSet[string]]::new()
foreach ($k in $allGpos.Keys) { [void]$unusedGuids.Add($k) }

# ---------- Build HTML (double quotes + numeric entities, no here-strings) ----------
$sb   = New-Object System.Text.StringBuilder
$css  = @(
"<style>",
"body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; }",
"h1 { margin-bottom: 0; }",
".subtle { color: #555; }",
".kv { font-family: ui-monospace, Consolas, monospace; }",
".badge { display:inline-block; padding:2px 6px; border-radius:8px; font-size:12px; margin-right:6px; border:1px solid #ccc; }",
".badge.enforced { background:#ffe9e9; border-color:#e09999; }",
".badge.disabled { background:#f5f5f5; }",
".badge.ok { background:#eaf7ea; border-color:#88b188; }",
".badge.warn { background:#fff7e0; border-color:#d9c06b; }",
".tree { margin: 0; padding-left: 20px; list-style-type: none; }",
".tree li { margin: 6px 0; }",
".tree li .title { font-weight:600; }",
"details { margin: 4px 0; }",
"summary { cursor: pointer; }",
".small { font-size: 12px; color:#666; }",
".meta { margin:2px 0 6px 0; }",
"code { background:#f6f6f6; padding:1px 4px; border-radius:4px; }",
".section { margin-top: 24px; }",
"hr { border:0; border-top:1px solid #ddd; margin:16px 0; }",
"table { border-collapse: collapse; }",
"td, th { padding: 6px 8px; border:1px solid #ddd; }",
"</style>"
) -join "`n"

$domainEsc = HtmlEsc $domain.DNSRoot
$nowStr    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

AddLine $sb "<!DOCTYPE html><html><head><meta charset=""utf-8""><title>GPO Tree Report - $domainEsc</title>$css</head><body>"
AddLine $sb "<h1>GPO Tree Report</h1><div class=""subtle"">Domain: <span class=""kv"">$domainEsc</span> &#8226; Generated: <span class=""kv"">$nowStr</span></div><hr />"
AddLine $sb "<div class=""section""><h2>OU &#8594; GPO Links</h2><ul class=""tree"">"

foreach ($ou in $ous) {
    $ouName = if ($ou -eq $domainRoot) { "Domain (root)" } else { $ou.Name }
    $dn = $ou.DistinguishedName
    $inheritanceBlocked = $false
    if ($ou.PSObject.Properties.Name -contains 'gPOptions') { $inheritanceBlocked = [bool]($ou.gPOptions -band 1) }

    AddLine $sb ("<li><span class=""title"">OU:</span> {0} <span class=""small kv"">({1})</span> " -f (HtmlEsc $ouName), (HtmlEsc $dn))
    if ($inheritanceBlocked) { AddLine $sb "<span class=""badge warn"">Inheritance Blocked</span>" }

    $links = Parse-gPLinkString -gPLink $ou.gPLink
    if (-not $links -or $links.Count -eq 0) {
        AddLine $sb "<div class=""small subtle"">(No linked GPOs)</div></li>"
        continue
    }

    AddLine $sb "<ul class=""tree"">"

    foreach ($l in $links) {
        [void]$linkedGuids.Add($l.Guid)
        [void]$unusedGuids.Remove($l.Guid)

        $gpo = $allGpos[$l.Guid]
        if (-not $gpo) {
            AddLine $sb ("<li><span class=""title"">Missing GPO:</span> {0}</li>" -f (HtmlEsc $l.Guid))
            continue
        }

        $guidStr = $gpo.Id.Guid.ToString()
        $xml     = $gpoXmlCache[$guidStr]
        $wmi     = $gpoWmiCache[$guidStr]
        $filters = $gpoFiltersCache[$guidStr]
        $settings= $gpoSettingsCache[$guidStr]
        $status  = $gpoStatusCache[$guidStr]

        AddLine $sb ("<li><div><span class=""title"">GPO:</span> {0} <span class=""small kv"">({1})</span> " -f (HtmlEsc $gpo.DisplayName), (HtmlEsc $guidStr))
        if ($l.Enforced)     { AddLine $sb "<span class=""badge enforced"">Enforced</span>" }
        if ($l.LinkDisabled) { AddLine $sb "<span class=""badge disabled"">Link Disabled</span>" }
        if ($status.UserSettingsDisabled)     { AddLine $sb "<span class=""badge warn"">User settings disabled</span>" }
        if ($status.ComputerSettingsDisabled) { AddLine $sb "<span class=""badge warn"">Computer settings disabled</span>" }
        if ($wmi) { AddLine $sb ("<span class=""badge ok"">WMI: {0}</span>" -f (HtmlEsc $wmi)) }
        AddLine $sb "</div>"

        # Meta row
        AddLine $sb ("<div class=""meta small""><b>Link Flags:</b> Enforced={0}, LinkEnabled={1} &#160; | &#160; <b>GPO Status:</b> {2}" -f ($(if($l.Enforced){'True'}else{'False'}), $(if($l.LinkDisabled){'False'}else{'True'}), (HtmlEsc $status.StatusString)))
        if ($filters -and $filters.Count) {
            AddLine $sb " &#160; | &#160; <b>Security Filtering:</b> "
            AddLine $sb (($filters | ForEach-Object { HtmlEsc $_ }) -join ", ")
        }
        AddLine $sb "</div>"

        # Settings
        AddLine $sb ("<details><summary>Settings ({0})</summary><ul class=""tree"">" -f $settings.Count)
        if ($settings.Count -gt 0) {
            foreach ($s in $settings) { AddLine $sb ("<li><code>{0}</code></li>" -f (HtmlEsc $s)) }
        } else {
            AddLine $sb "<li class=""small subtle"">(No explicit settings parsed or not applicable)</li>"
        }
        AddLine $sb "</ul></details>"

        AddLine $sb "</li>"
    }

    AddLine $sb "</ul></li>"
}

AddLine $sb "</ul></div>"

# Summary + efficiency lists
$gposUserDisabled     = @()
$gposComputerDisabled = @()
foreach ($kv in $gpoStatusCache.GetEnumerator()) {
    $guid = $kv.Key
    $gpo  = $allGpos[$guid]
    if (-not $gpo) { continue }
    if ($kv.Value.UserSettingsDisabled)     { $gposUserDisabled     += $gpo }
    if ($kv.Value.ComputerSettingsDisabled) { $gposComputerDisabled += $gpo }
}

AddLine $sb "<div class=""section""><h2>Summary</h2><table><tbody>"
AddLine $sb ("<tr><th>Total OUs</th><td>{0}</td></tr>" -f ($ous.Count))
AddLine $sb ("<tr><th>Total GPOs</th><td>{0}</td></tr>" -f ($allGpos.Count))
AddLine $sb ("<tr><th>Linked GPOs</th><td>{0}</td></tr>" -f ($linkedGuids.Count))
AddLine $sb ("<tr><th>Unused GPOs</th><td>{0}</td></tr>" -f ($unusedGuids.Count))
AddLine $sb "</tbody></table>"

AddLine $sb "<div style=""margin-top:10px"">"
AddLine $sb "<details><summary><b>GPOs with User settings disabled</b> (for efficiency)</summary><ul class=""tree"">"
if ($gposUserDisabled) {
    foreach ($g in ($gposUserDisabled | Sort-Object DisplayName)) {
        AddLine $sb ("<li>{0} <span class=""small kv"">({1})</span></li>" -f (HtmlEsc $g.DisplayName), (HtmlEsc $g.Id.Guid.ToString()))
    }
} else {
    AddLine $sb "<li class=""small subtle"">(None)</li>"
}
AddLine $sb "</ul></details>"

AddLine $sb "<details><summary><b>GPOs with Computer settings disabled</b> (for efficiency)</summary><ul class=""tree"">"
if ($gposComputerDisabled) {
    foreach ($g in ($gposComputerDisabled | Sort-Object DisplayName)) {
        AddLine $sb ("<li>{0} <span class=""small kv"">({1})</span></li>" -f (HtmlEsc $g.DisplayName), (HtmlEsc $g.Id.Guid.ToString()))
    }
} else {
    AddLine $sb "<li class=""small subtle"">(None)</li>"
}
AddLine $sb "</ul></details>"
AddLine $sb "</div></div>"

# Unused GPOs
AddLine $sb "<div class=""section""><h2>Unused GPOs</h2>"
if ($unusedGuids.Count -eq 0) {
    AddLine $sb "<div class=""small subtle"">(None)</div>"
} else {
    AddLine $sb "<ul class=""tree"">"
    foreach ($guid in ($unusedGuids | Sort-Object)) {
        $g = $allGpos[$guid]; if (-not $g) { continue }
        $xml     = $gpoXmlCache[$guid]
        $wmi     = $gpoWmiCache[$guid]
        $filters = $gpoFiltersCache[$guid]
        $settings= $gpoSettingsCache[$guid]
        $status  = $gpoStatusCache[$guid]

        AddLine $sb ("<li><div><span class=""title"">GPO:</span> {0} <span class=""small kv"">({1})</span> " -f (HtmlEsc $g.DisplayName), (HtmlEsc $g.Id.Guid.ToString()))
        if ($status.UserSettingsDisabled)     { AddLine $sb "<span class=""badge warn"">User settings disabled</span>" }
        if ($status.ComputerSettingsDisabled) { AddLine $sb "<span class=""badge warn"">Computer settings disabled</span>" }
        if ($wmi) { AddLine $sb ("<span class=""badge ok"">WMI: {0}</span>" -f (HtmlEsc $wmi)) }
        AddLine $sb "</div>"

        if ($filters -and $filters.Count) {
            AddLine $sb "<div class=""meta small""><b>Security Filtering:</b> "
            AddLine $sb (($filters | ForEach-Object { HtmlEsc $_ }) -join ", ")
            AddLine $sb "</div>"
        }

        AddLine $sb ("<details><summary>Settings ({0})</summary><ul class=""tree"">" -f $settings.Count)
        if ($settings.Count -gt 0) {
            foreach ($s in $settings) { AddLine $sb ("<li><code>{0}</code></li>" -f (HtmlEsc $s)) }
        } else {
            AddLine $sb "<li class=""small subtle"">(No explicit settings parsed or not applicable)</li>"
        }
        AddLine $sb "</ul></details>"

        AddLine $sb "</li>"
    }
    AddLine $sb "</ul>"
}
AddLine $sb "</div>"

AddLine $sb "<hr /><div class=""small subtle"">Tip: Disabling the unused half (User/Computer) can reduce processing time.</div>"
AddLine $sb "</body></html>"

# Write file
try {
    $html = $sb.ToString()
    $dir = Split-Path -Path $OutputPath -Parent
    if ($dir -and -not (Test-Path -Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText((Resolve-Path -LiteralPath $OutputPath), $html, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Report written to: $OutputPath"
} catch {
    Write-Error "Failed to write HTML report: $_"
}
