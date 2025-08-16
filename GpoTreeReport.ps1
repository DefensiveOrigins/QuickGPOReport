<#
.SYNOPSIS
  Generate an HTML tree report of Group Policy application with per-setting lines, stdout progress, and robust parsing.

.REQUIREMENTS
  RSAT modules: ActiveDirectory, GroupPolicy
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\GpoTreeReport.html"
)

# --- Prereqs ---
$modules = @("ActiveDirectory","GroupPolicy")
foreach ($m in $modules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Error "Required module '$m' is not available. Install/enable RSAT ($m) and re-run."
        return
    }
}
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

# --- Helpers ---

function Get-GpoSecurityFilters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GpoName
    )
    $list = @()
    try {
        # Ensure the cmdlet exists (older RSAT installs or minimal servers may lack it)
        if (-not (Get-Command Get-GPPermission -ErrorAction SilentlyContinue)) {
            Write-Verbose "Get-GPPermission not available; skipping security filtering for '$GpoName'."
            return $list
        }

        $perms = Get-GPPermission -Name $GpoName -All -ErrorAction Stop
        foreach ($p in $perms) {
            if ($p.Permission -eq 'GpoApply' -and $p.Type -eq 'Allow') {
                $list += $p.Trustee.Name
            }
        }
    } catch {
        Write-Verbose "Get-GpoSecurityFilters failed for '$GpoName': $_"
    }
    return ($list | Sort-Object -Unique)
}

function HtmlEsc([string]$s) {
    if ($null -eq $s) { return "" }
    ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function AddLine([System.Text.StringBuilder]$sb, [string]$text) {
    [void]$sb.Append($text)
}

function Get-GpoStatusInfo($gpoObj, [xml]$gpoXml) {
    $status = $null
    if ($gpoObj -and $gpoObj.PSObject.Properties.Name -contains 'GpoStatus') {
        $status = [string]$gpoObj.GpoStatus
    }
    if (-not $status -and $gpoXml -and $gpoXml.GPO.GpoStatus) {
        $status = [string]$gpoXml.GPO.GpoStatus
    }
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

function Get-GpoReportXmlByGuid([guid]$Guid) {
    try { [xml](Get-GPOReport -Guid $Guid -ReportType Xml -ErrorAction Stop) } catch { $null }
}

# --- SETTINGS ENUMERATION (XML first, then HTML fallback) ---

# XML: aggressive schema coverage
function Get-GpoSettingLinesFromXml([xml]$GpoXml) {
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

        if (-not $parts) {
            $text = ($node.InnerText -replace '\s+',' ').Trim()
            if ($text) { $parts += $text }
        }

        if ($parts.Count) { $lines.Add(($parts -join " | ")) }
    }

    # Any <Policy> node
    $policyNodes = $GpoXml.SelectNodes("//GPO//*[local-name()='Policy']")
    foreach ($n in $policyNodes) { Grab -node $n -side (Get-SideTag $n) }

    # Registry Preferences
    $regNodes = $GpoXml.SelectNodes("//GPO//RegistrySettings/RegistrySetting")
    foreach ($n in $regNodes) {
        $side = Get-SideTag $n
        $lines.Add(("{0} RegistryPreference | Action={1} | Key={2} | ValueName={3} | Data={4} | Type={5}" -f $side,$n.Action,$n.Key,$n.ValueName,$n.Data,$n.Type).Trim())
    }

    # Generic Preferences (Files, Shortcuts, Tasks, etc.) — nodes with an 'action' attribute
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

    # Scripts
    $scriptNodes = $GpoXml.SelectNodes("//GPO//Scripts/*/Script")
    foreach ($s in $scriptNodes) {
        $phase = $s.ParentNode.Name
        $cmd   = $s.Command
        $pars  = $s.Parameters
        $side  = Get-SideTag $s
        $lines.Add(("{0} Script:{1} | {2} {3}" -f $side,$phase,$cmd,$pars).Trim())
    }

    # Common SecEdit summaries
    foreach ($nodeName in @("Account","Kerberos","Audit","EventAudit","PasswordPolicy","KerberosPolicy")) {
        $nodes = $GpoXml.SelectNodes("//GPO//Computer/$nodeName/*")
        foreach ($n in $nodes) {
            $txt = ($n.OuterXml -replace '<.*?>',' ' -replace '\s+',' ').Trim()
            if ($txt) { $lines.Add(("[Computer] {0} | {1}" -f $nodeName, $txt)) }
        }
    }

    ($lines | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique)
}

# HTML fallback: parse the HTML table rows into "one-line" settings
function Get-GpoSettingLinesFromHtml([string]$HtmlText) {
    $out = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($HtmlText)) { return $out }

    # Normalize whitespace
    $h = $HtmlText -replace "`r","" -replace "`n"," "

    # Roughly pull rows from HTML setting tables; extract first 2-3 cells as "Name | Value | Extra"
    $rowMatches = [regex]::Matches($h, "<tr[^>]*>(.*?)</tr>", "IgnoreCase")
    foreach ($rm in $rowMatches) {
        $row = $rm.Groups[1].Value
        $cells = [regex]::Matches($row, "<t[dh][^>]*>(.*?)</t[dh]>", "IgnoreCase")
        if ($cells.Count -ge 1) {
            $vals = @()
            foreach ($c in $cells) {
                $txt = $c.Groups[1].Value
                # strip remaining tags & compress spaces
                $txt = ($txt -replace "<.*?>"," " -replace "\s+"," ").Trim()
                if ($txt) { $vals += $txt }
            }
            if ($vals.Count -gt 0) {
                # Heuristic: keep it short & useful
                $line = $vals[0]
                if ($vals.Count -gt 1) { $line += " | " + $vals[1] }
                if ($vals.Count -gt 2 -and $vals[2] -notmatch '^Not Configured$') { $line += " | " + $vals[2] }
                if ($line -and $line -notmatch '^\s*(Setting|Policy|Name)\s*$') {
                    $out.Add($line)
                }
            }
        }
    }

    ($out | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique)
}

# Returns settings, trying XML first; if empty, tries HTML
function Get-GpoSettingLines([xml]$XmlReport, [string]$HtmlReport) {
    $fromXml  = Get-GpoSettingLinesFromXml -GpoXml $XmlReport
    if ($fromXml.Count -gt 0) { return $fromXml }
    Get-GpoSettingLinesFromHtml -HtmlText $HtmlReport
}

# --- Collect GPOs and cache reports (with stdout progress) ---
$allGpos = Get-GPO -All
Write-Host "Discovered $($allGpos.Count) GPO(s) in the domain."

$gpoXmlCache      = @{}
$gpoHtmlCache     = @{}
$gpoWmiCache      = @{}
$gpoFiltersCache  = @{}
$gpoSettingsCache = @{}
$gpoStatusCache   = @{}

$totalSettings = 0
foreach ($gpo in $allGpos) {
    try {
        $xml  = Get-GpoReportXmlByGuid -Guid $gpo.Id
        $html = $null
        try { $html = Get-GPOReport -Guid $gpo.Id -ReportType Html -ErrorAction Stop } catch { }

        $gpoXmlCache[$gpo.Id.Guid.ToString()]  = $xml
        $gpoHtmlCache[$gpo.Id.Guid.ToString()] = $html
        $gpoWmiCache[$gpo.Id.Guid.ToString()]  = if ($xml) { 
            $w = $xml.GPO.WMIFilter
            if ($w -and $w.Name) { if ($w.Query) { "{0} ({1})" -f $w.Name, ($w.Query -replace '\s+',' ') } else { $w.Name } } else { $null }
        } else { $null }
        $gpoFiltersCache[$gpo.Id.Guid.ToString()] = Get-GpoSecurityFilters -GpoName $gpo.DisplayName
        $gpoStatusCache[$gpo.Id.Guid.ToString()]  = Get-GpoStatusInfo -gpoObj $gpo -gpoXml $xml

        $settings = Get-GpoSettingLines -XmlReport $xml -HtmlReport $html
        $gpoSettingsCache[$gpo.Id.Guid.ToString()] = $settings
        $totalSettings += $settings.Count

        Write-Host ("  GPO: {0} -> {1} setting(s)" -f $gpo.DisplayName, $settings.Count)
    } catch {
        Write-Warning "Failed to parse $($gpo.DisplayName): $_"
    }
}
Write-Host "Total settings parsed across all GPOs: $totalSettings"

# --- Gather OUs and Domain Root for tree ---
$domain = Get-ADDomain
$ouList = Get-ADOrganizationalUnit -Filter * -Properties Name,DistinguishedName | Sort-Object DistinguishedName
$targets = @("DomainRoot") + ($ouList | ForEach-Object { $_.DistinguishedName })

# --- Track linked vs unused GPOs ---
$linkedGuids = [System.Collections.Generic.HashSet[string]]::new()
$allGuidSet  = [System.Collections.Generic.HashSet[string]]::new()
foreach ($g in $allGpos) { [void]$allGuidSet.Add($g.Id.Guid.ToString()) }

# --- Build HTML (double quotes; numeric entities for separators) ---
$sb  = New-Object System.Text.StringBuilder
$css = @(
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

foreach ($t in $targets) {
    if ($t -eq "DomainRoot") {
        $label = "Domain (root)"
        $targetDN = $domain.DistinguishedName
    } else {
        $ouObj = Get-ADObject -Identity $t -Properties Name,DistinguishedName
        $label = $ouObj.Name
        $targetDN = $ouObj.DistinguishedName
    }

    $inheritance = Get-GPInheritance -Target $targetDN
    $inheritanceBlocked = $inheritance.BlockInheritance

    AddLine $sb ("<li><span class=""title"">OU:</span> {0} <span class=""small kv"">({1})</span> " -f (HtmlEsc $label), (HtmlEsc $targetDN))
    if ($inheritanceBlocked) { AddLine $sb "<span class=""badge warn"">Inheritance Blocked</span>" }

    if (-not $inheritance.GpoLinks -or $inheritance.GpoLinks.Count -eq 0) {
        AddLine $sb "<div class=""small subtle"">(No linked GPOs)</div></li>"
        continue
    }

    AddLine $sb "<ul class=""tree"">"
    foreach ($link in $inheritance.GpoLinks) {
        $guidStr = $link.GpoId.Guid.ToString()
        [void]$linkedGuids.Add($guidStr)

        $gpo = ($allGpos | Where-Object { $_.Id.Guid -eq $link.GpoId.Guid })
        if (-not $gpo) {
            AddLine $sb ("<li><span class=""title"">Missing GPO:</span> {0}</li>" -f (HtmlEsc $guidStr))
            continue
        }

        $xml      = $gpoXmlCache[$guidStr]
        $html     = $gpoHtmlCache[$guidStr]
        $wmi      = $gpoWmiCache[$guidStr]
        $filters  = $gpoFiltersCache[$guidStr]
        $settings = $gpoSettingsCache[$guidStr]
        $status   = $gpoStatusCache[$guidStr]

        AddLine $sb ("<li><div><span class=""title"">GPO:</span> {0} <span class=""small kv"">({1})</span> " -f (HtmlEsc $gpo.DisplayName), (HtmlEsc $guidStr))
        if ($link.Enforced) { AddLine $sb "<span class=""badge enforced"">Enforced</span>" }
        if (-not $link.Enabled) { AddLine $sb "<span class=""badge disabled"">Link Disabled</span>" }
        if ($status.UserSettingsDisabled)     { AddLine $sb "<span class=""badge warn"">User settings disabled</span>" }
        if ($status.ComputerSettingsDisabled) { AddLine $sb "<span class=""badge warn"">Computer settings disabled</span>" }
        if ($wmi) { AddLine $sb ("<span class=""badge ok"">WMI: {0}</span>" -f (HtmlEsc $wmi)) }
        AddLine $sb "</div>"

        AddLine $sb ("<div class=""meta small""><b>Link Flags:</b> Enforced={0}, LinkEnabled={1} &#160; | &#160; <b>GPO Status:</b> {2}" -f ($(if($link.Enforced){'True'}else{'False'}), $(if($link.Enabled){'True'}else{'False'}), (HtmlEsc $status.StatusString)))
        if ($filters -and $filters.Count) {
            AddLine $sb " &#160; | &#160; <b>Security Filtering:</b> "
            AddLine $sb (($filters | ForEach-Object { HtmlEsc $_ }) -join ", ")
        }
        AddLine $sb "</div>"

        AddLine $sb ("<details><summary>Settings ({0})</summary><ul class=""tree"">" -f $settings.Count)
        if ($settings.Count -gt 0) {
            foreach ($s in $settings) { AddLine $sb ("<li><code>{0}</code></li>" -f (HtmlEsc $s)) }
        } else {
            # If XML cache was empty but we do have the raw HTML, give a hint inside the report too.
            if ($html) {
                $fallbackLines = Get-GpoSettingLinesFromHtml -HtmlText $html
                if ($fallbackLines.Count -gt 0) {
                    foreach ($s in $fallbackLines) { AddLine $sb ("<li><code>{0}</code></li>" -f (HtmlEsc $s)) }
                } else {
                    AddLine $sb "<li class=""small subtle"">(No explicit settings parsed or not applicable)</li>"
                }
            } else {
                AddLine $sb "<li class=""small subtle"">(No explicit settings parsed or not applicable)</li>"
            }
        }
        AddLine $sb "</ul></details>"

        AddLine $sb "</li>"
    }
    AddLine $sb "</ul></li>"
}
AddLine $sb "</ul></div>"

# --- Summary + Efficiency lists ---
$gposUserDisabled     = @()
$gposComputerDisabled = @()
foreach ($g in $allGpos) {
    $st = $gpoStatusCache[$g.Id.Guid.ToString()]
    if ($st.UserSettingsDisabled)     { $gposUserDisabled     += $g }
    if ($st.ComputerSettingsDisabled) { $gposComputerDisabled += $g }
}

AddLine $sb "<div class=""section""><h2>Summary</h2><table><tbody>"
AddLine $sb ("<tr><th>Total OUs (incl. root)</th><td>{0}</td></tr>" -f $targets.Count)
AddLine $sb ("<tr><th>Total GPOs</th><td>{0}</td></tr>" -f $allGpos.Count)
AddLine $sb ("<tr><th>Linked GPOs</th><td>{0}</td></tr>" -f $linkedGuids.Count)
AddLine $sb ("<tr><th>Unused GPOs</th><td>{0}</td></tr>" -f ($allGuidSet.Count - $linkedGuids.Count))
AddLine $sb ("<tr><th>Total Settings Parsed</th><td>{0}</td></tr>" -f $totalSettings)
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

# --- Unused GPOs ---
$unusedGuids = [System.Collections.Generic.HashSet[string]]::new()
foreach ($k in $allGuidSet) { if (-not $linkedGuids.Contains($k)) { [void]$unusedGuids.Add($k) } }

AddLine $sb "<div class=""section""><h2>Unused GPOs</h2>"
if ($unusedGuids.Count -eq 0) {
    AddLine $sb "<div class=""small subtle"">(None)</div>"
} else {
    AddLine $sb "<ul class=""tree"">"
    foreach ($guid in ($unusedGuids | Sort-Object)) {
        $g = $allGpos | Where-Object { $_.Id.Guid.ToString() -eq $guid }
        if (-not $g) { continue }
        $xml      = $gpoXmlCache[$guid]
        $html     = $gpoHtmlCache[$guid]
        $wmi      = $gpoWmiCache[$guid]
        $filters  = $gpoFiltersCache[$guid]
        $settings = $gpoSettingsCache[$guid]
        $status   = $gpoStatusCache[$guid]

        AddLine $sb ("<li><div><span class=""title"">GPO:</span> {0} <span class=""small kv"">({1})</span> " -f (HtmlEsc $g.DisplayName), (HtmlEsc $guid))
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
            if ($html) {
                $fallbackLines = Get-GpoSettingLinesFromHtml -HtmlText $html
                if ($fallbackLines.Count -gt 0) {
                    foreach ($s in $fallbackLines) { AddLine $sb ("<li><code>{0}</code></li>" -f (HtmlEsc $s)) }
                } else {
                    AddLine $sb "<li class=""small subtle"">(No explicit settings parsed or not applicable)</li>"
                }
            } else {
                AddLine $sb "<li class=""small subtle"">(No explicit settings parsed or not applicable)</li>"
            }
        }
        AddLine $sb "</ul></details>"

        AddLine $sb "</li>"
    }
    AddLine $sb "</ul>"
}
AddLine $sb "</div>"

AddLine $sb "<hr /><div class=""small subtle"">Tip: Disabling the unused half (User/Computer) can reduce processing time.</div>"
AddLine $sb "</body></html>"

# --- Write HTML Report (ensure directory exists, no inline 'if') ---
try {
    $reportDir = Split-Path -Parent $OutputPath
    if ($reportDir -and -not (Test-Path -LiteralPath $reportDir)) {
        Write-Host "Creating report directory: $reportDir"
        New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    }

    # Resolve to absolute path safely (no inline if)
    if ([System.IO.Path]::IsPathRooted($OutputPath)) {
        $resolvedOut = $OutputPath
    } else {
        $resolvedOut = Join-Path -Path (Get-Location) -ChildPath $OutputPath
    }
    $resolvedOut = [System.IO.Path]::GetFullPath($resolvedOut)

    $html = $sb.ToString()
    [System.IO.File]::WriteAllText($resolvedOut, $html, [System.Text.UTF8Encoding]::new($false))
    Write-Host "HTML report written to $resolvedOut"
} catch {
    Write-Error "Failed to write HTML report: $_"
}
