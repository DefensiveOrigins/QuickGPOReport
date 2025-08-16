<#
.SYNOPSIS
    Generate an HTML tree report of Group Policy Objects (GPOs) and their application.

.DESCRIPTION
    This script lists all Group Policy Objects in the environment in a tree format.
    The report includes:
        - OU structure with linked GPOs
        - Unused GPOs
        - GPO filters (Security, WMI, Enforced, Inheritance blocking)
        - Whether User/Computer settings are disabled
        - Enumerated settings inside each GPO (single-line format)
    Outputs an HTML report and prints progress to stdout.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\GpoTreeReport.html"
)

Import-Module GroupPolicy

# Helpers
function HtmlEsc($text) {
    return [System.Web.HttpUtility]::HtmlEncode($text)
}
function AddLine([System.Text.StringBuilder]$sb, [string]$line) {
    $null = $sb.AppendLine($line)
}

# --- SETTINGS ENUMERATION ---
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
        $disp  = $node.GetAttribute("displayName")
        if (-not $disp) { $disp = $node.GetAttribute("name") }
        if (-not $disp -and $node.SelectSingleNode("displayName")) { $disp = $node.SelectSingleNode("displayName").InnerText }

        $state = $node.GetAttribute("state")
        if (-not $state) {
            $enabledAttr = $node.GetAttribute("enabled")
            $disabledAttr= $node.GetAttribute("disabled")
            if ($enabledAttr)  { $state = "Enabled=$enabledAttr" }
            elseif ($disabledAttr) { $state = "Disabled=$disabledAttr" }
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

    # Policies
    $policyNodes = $GpoXml.SelectNodes("//GPO//*[local-name()='Policy']")
    foreach ($n in $policyNodes) { Grab -node $n -side (Get-SideTag $n) }

    # Registry Prefs
    $regNodes = $GpoXml.SelectNodes("//GPO//RegistrySettings/RegistrySetting")
    foreach ($n in $regNodes) {
        $side = Get-SideTag $n
        $lines.Add(("{0} RegistryPreference | Action={1} | Key={2} | ValueName={3} | Data={4} | Type={5}" -f $side,$n.Action,$n.Key,$n.ValueName,$n.Data,$n.Type).Trim())
    }

    # Generic Prefs
    $prefNodes = $GpoXml.SelectNodes("//GPO//*[local-name()='Preferences']//*[@action]")
    foreach ($n in $prefNodes) {
        $side = Get-SideTag $n
        $type = $n.Name
        $action = $n.GetAttribute("action")
        $name = $n.GetAttribute("name")
        $path = $n.GetAttribute("path"); if (-not $path) { $path = $n.GetAttribute("targetPath") }
        $desc = $n.GetAttribute("description")

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

    # SecEdit (account/audit/etc.)
    foreach ($nodeName in @("Account","Kerberos","Audit","EventAudit","PasswordPolicy","KerberosPolicy")) {
        $nodes = $GpoXml.SelectNodes("//GPO//Computer/$nodeName/*")
        foreach ($n in $nodes) {
            $txt = ($n.OuterXml -replace '<.*?>',' ' -replace '\s+',' ').Trim()
            if ($txt) { $lines.Add(("[Computer] {0} | {1}" -f $nodeName, $txt)) }
        }
    }

    ($lines | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique)
}

# --- MAIN ---
$allGpos = Get-GPO -All
Write-Host "Discovered $($allGpos.Count) GPOs in the domain."

$totalSettings = 0
$gpoXmlCache = @{}

foreach ($gpo in $allGpos) {
    try {
        $xmlText = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        [xml]$xml = $xmlText
        $gpoXmlCache[$gpo.Id] = $xml
        $settings = Get-GpoSettingLines -GpoXml $xml
        $totalSettings += $settings.Count
        Write-Host ("  GPO: {0} -> {1} settings" -f $gpo.DisplayName, $settings.Count)
    } catch {
        Write-Warning "Failed to parse $($gpo.DisplayName): $_"
    }
}
Write-Host "Total settings parsed across all GPOs: $totalSettings"

# Build HTML
$sb = New-Object System.Text.StringBuilder
AddLine $sb "<html><head><meta charset='utf-8'><title>GPO Tree Report</title>"
AddLine $sb "<style>body{font-family:Segoe UI,Arial;} ul{list-style-type:none;} .gpo{margin-left:20px;} .badge{padding:2px 4px; border-radius:4px; font-size:0.8em; margin-left:4px;} .enforced{background:#d9534f;color:white;} .warn{background:#f0ad4e;color:white;} .ok{background:#5cb85c;color:white;} .small{font-size:0.9em;color:#666;} details{margin:4px 0;} summary{cursor:pointer;} </style>"
AddLine $sb "</head><body>"
AddLine $sb "<h1>Group Policy Tree Report</h1>"
AddLine $sb "<p>Discovered $($allGpos.Count) GPOs, with $totalSettings settings across all policies.</p>"

# OUs with linked GPOs
$roots = Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName
foreach ($ou in $roots) {
    $links = Get-GPInheritance -Target $ou.DistinguishedName
    $inheritanceBlocked = $links.BlockInheritance

    AddLine $sb "<ul><li><b>OU:</b> $(HtmlEsc $ou.Name) <span class='small kv'>($($ou.DistinguishedName))</span>"
    if ($inheritanceBlocked) { AddLine $sb "<span class='badge warn'>Inheritance Blocked</span>" }

    if ($links.GpoLinks.Count -eq 0) {
        AddLine $sb "<div class='small subtle'>(No linked GPOs)</div></li></ul>"
        continue
    }

    AddLine $sb "<ul>"
    foreach ($l in $links.GpoLinks) {
        $gpo = $allGpos | Where-Object { $_.DisplayName -eq $l.DisplayName }
        if (-not $gpo) { continue }
        $xml = $gpoXmlCache[$gpo.Id]
        $settings = Get-GpoSettingLines -GpoXml $xml

        AddLine $sb "<li class='gpo'><b>GPO:</b> $(HtmlEsc $gpo.DisplayName)"
        if ($l.Enforced) { AddLine $sb "<span class='badge enforced'>Enforced</span>" }
        if ($l.WmiFilter) { AddLine $sb "<span class='badge ok'>WMI: $(HtmlEsc $l.WmiFilter.Name)</span>" }
        AddLine $sb " &nbsp;&nbsp; <b>Status:</b> $($gpo.GpoStatus)"

        AddLine $sb "<details><summary>Settings ($($settings.Count))</summary><ul>"
        foreach ($s in $settings) {
            AddLine $sb "<li>$(HtmlEsc $s)</li>"
        }
        AddLine $sb "</ul></details></li>"
    }
    AddLine $sb "</ul></li></ul>"
}

# Unused GPOs
$linkedGuids = @()
foreach ($ou in $roots) {
    $links = Get-GPInheritance -Target $ou.DistinguishedName
    foreach ($l in $links.GpoLinks) { if ($l) { $linkedGuids += $l.GpoId } }
}
$unused = $allGpos | Where-Object { $linkedGuids -notcontains $_.Id }
AddLine $sb "<h2>Unused GPOs</h2><ul>"
foreach ($g in $unused) {
    $xml = $gpoXmlCache[$g.Id]
    $settings = Get-GpoSettingLines -GpoXml $xml
    AddLine $sb "<li><b>$(HtmlEsc $g.DisplayName)</b> &nbsp;&nbsp;<b>Status:</b> $($g.GpoStatus)"
    AddLine $sb "<details><summary>Settings ($($settings.Count))</summary><ul>"
    foreach ($s in $settings) {
        AddLine $sb "<li>$(HtmlEsc $s)</li>"
    }
    AddLine $sb "</ul></details></li>"
}
AddLine $sb "</ul>"

AddLine $sb "</body></html>"
$sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "HTML report written to $OutputPath"
