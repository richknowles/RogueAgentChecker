<#
    Report.ps1 - writes the scan result to disk:
        <base>.html   self-contained report for managers and auditors (no external
                      fonts, scripts or images; opens offline, prints cleanly)
        <base>.csv    one row per finding, for Excel or a SIEM
        <base>.json   the full scan result, for later tooling (GUI, VS Code)
    Every string passes through Protect-RacText one more time on the way out.
#>

$script:RacCategoryLabels = [ordered]@{
    'Processes'        = '1. Processes'
    'Network'          = '2. Network'
    'ConfigAndSecrets' = '3. Config, memory & secrets'
    'Persistence'      = '4. Persistence'
    'TokensAndOAuth'   = '5. Tokens & OAuth'
    'LogsAndEvents'    = '6. Logs & events'
    'Behavior'         = '7. Behavior'
}

function ConvertTo-RacHtml {
    <# HTML-encode after a final redaction pass. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $text = $Value
    if ($Value -is [datetime]) { $text = $Value.ToString('yyyy-MM-dd HH:mm') }
    return [System.Net.WebUtility]::HtmlEncode((Protect-RacText -Text ([string]$text)))
}

function Get-RacClassRank {
    param([string]$Classification)
    switch ($Classification) { 'Suspicious' { return 0 } 'Unknown' { return 1 } default { return 2 } }
}

function ConvertTo-RacExportRecord {
    <# Flattens a finding for CSV / JSON. Internal fields are left out. #>
    param($Finding, [string]$ComputerName)
    $evidenceText = (@($Finding.Evidence.Keys) | ForEach-Object { '{0}={1}' -f $_, $Finding.Evidence[$_] }) -join ' | '
    $eventTime = ''
    if ($Finding.EventTime -is [datetime]) { $eventTime = $Finding.EventTime.ToString('yyyy-MM-dd HH:mm:ss') }
    [pscustomobject]@{
        FindingId      = $Finding.FindingId
        Classification = $Finding.Classification
        Score          = $Finding.Score
        Category       = $Finding.Category
        Breadcrumb     = $Finding.Breadcrumb
        Agent          = $Finding.Agent
        AgentId        = $Finding.AgentId
        Title          = (Protect-RacText -Text $Finding.Title)
        User           = $Finding.User
        Computer       = $ComputerName
        Location       = (Protect-RacText -Text $Finding.Location)
        EventTime      = $eventTime
        Indicators     = (@($Finding.Indicators) -join '; ')
        AllowListEntry = $Finding.AllowListEntry
        Evidence       = (Protect-RacText -Text $evidenceText)
        Reasons        = (Protect-RacText -Text (@($Finding.Reasons) -join ' '))
        Recommendation = $Finding.Recommendation
    }
}

function Export-RacFindingCsv {
    param($ScanResult, [string]$Path)
    $rows = @($ScanResult.Findings | ForEach-Object { ConvertTo-RacExportRecord -Finding $_ -ComputerName $ScanResult.ComputerName })
    # Excel needs a byte-order mark to read UTF-8 correctly. Windows PowerShell's
    # 'UTF8' writes one; PowerShell 7 needs 'utf8BOM' for the same result.
    $encoding = 'UTF8'
    if ($PSVersionTable.PSVersion.Major -ge 6) { $encoding = 'utf8BOM' }
    if ($rows.Count -eq 0) {
        Set-Content -LiteralPath $Path -Value '"FindingId","Classification","Score","Category","Breadcrumb","Agent","AgentId","Title","User","Computer","Location","EventTime","Indicators","AllowListEntry","Evidence","Reasons","Recommendation"' -Encoding $encoding
    }
    else {
        $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding $encoding
    }
}

function Export-RacFindingJson {
    param($ScanResult, [string]$Path)
    $doc = [ordered]@{
        tool         = 'Rogue Agent Checker'
        toolVersion  = $ScanResult.ToolVersion
        scanId       = $ScanResult.ScanId
        computerName = $ScanResult.ComputerName
        startTime    = $ScanResult.StartTime.ToString('o')
        endTime      = $ScanResult.EndTime.ToString('o')
        runAs        = $ScanResult.RunAs
        elevated     = $ScanResult.Elevated
        powerShell   = $ScanResult.PowerShellVersion
        os           = $ScanResult.OperatingSystem
        parameters   = $ScanResult.Parameters
        signatures   = [ordered]@{ path = $ScanResult.SignatureFile; version = $ScanResult.SignatureVersion; sha256 = $ScanResult.SignatureSha256 }
        allowList    = [ordered]@{ path = $ScanResult.AllowListFile; sha256 = $ScanResult.AllowListSha256; entries = $ScanResult.AllowListEntryCount; warnings = @($ScanResult.AllowListWarnings) }
        summary      = $ScanResult.Summary
        coverage     = @($ScanResult.Coverage)
        findings     = @($ScanResult.Findings | ForEach-Object {
                $r = ConvertTo-RacExportRecord -Finding $_ -ComputerName $ScanResult.ComputerName
                $evidence = [ordered]@{}
                foreach ($k in $_.Evidence.Keys) { $evidence[$k] = Protect-RacText -Text ([string]$_.Evidence[$k]) }
                [ordered]@{
                    findingId = $r.FindingId; classification = $r.Classification; score = $r.Score
                    category = $r.Category; breadcrumb = $r.Breadcrumb; agent = $r.Agent; agentId = $r.AgentId
                    title = $r.Title; user = $r.User; location = $r.Location; eventTime = $r.EventTime
                    indicators = @($_.Indicators); allowListEntry = $r.AllowListEntry
                    evidence = $evidence; reasons = @($_.Reasons | ForEach-Object { Protect-RacText -Text $_ })
                    recommendation = $r.Recommendation
                }
            })
    }
    $json = $doc | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Get-RacNextStep {
    <# Ordered, plain-language action list for the top of the report. #>
    param($ScanResult)

    $steps = @()
    $findings = @($ScanResult.Findings)
    $suspicious = @($findings | Where-Object { $_.Classification -eq 'Suspicious' })
    $unknown = @($findings | Where-Object { $_.Classification -eq 'Unknown' })

    if ($suspicious.Count -gt 0) {
        $list = ($suspicious | Select-Object -First 8 | ForEach-Object {
                $short = $_.Title
                if ($short.Length -gt 70) { $short = $short.Substring(0, 67) + '...' }
                '{0} {1}' -f $_.FindingId, $short
            }) -join '; '
        $more = ''
        if ($suspicious.Count -gt 8) { $more = (' and {0} more' -f ($suspicious.Count - 8)) }
        $steps += ('Investigate the {0} suspicious finding(s) first: {1}{2}. Preserve evidence before removing anything.' -f $suspicious.Count, $list, $more)
    }

    $exposed = @($findings | Where-Object { $_.Classification -ne 'Trusted' -and ($_.Indicators -contains 'SecretWorldReadable' -or $_.Indicators -contains 'MachineWideSecret' -or ($_.Breadcrumb -eq 'SecretFile' -and $_.Classification -eq 'Suspicious')) })
    if ($exposed.Count -gt 0) {
        $steps += ('Rotate exposed AI keys at the provider and move them into a secret store: {0}.' -f (($exposed | ForEach-Object { $_.FindingId }) -join ', '))
    }

    $listeners = @($findings | Where-Object { $_.Indicators -contains 'ListensOnAllInterfaces' })
    if ($listeners.Count -gt 0) {
        $steps += ('Close network-exposed agent or model ports (bind to 127.0.0.1 or firewall them): {0}.' -f (($listeners | ForEach-Object { $_.FindingId }) -join ', '))
    }

    if ($unknown.Count -gt 0) {
        $agents = @($unknown | ForEach-Object { $_.Agent } | Select-Object -Unique)
        $steps += ('Assign an owner to each of the {0} unknown item(s) across {1} agent(s) and decide: approve (add to the allow-list with an approver and expiry) or remove through change control.' -f $unknown.Count, $agents.Count)
    }

    $gaps = @($ScanResult.Coverage | Where-Object { $_.Status -eq 'Skipped' -or $_.Status -eq 'Partial' -or $_.Status -eq 'Error' })
    if ($gaps.Count -gt 0 -and -not $ScanResult.Elevated) {
        $steps += ('Close coverage gaps: {0} source(s) were partial or skipped. Rerun from an elevated PowerShell to cover other users, the Security log and WMI subscriptions.' -f $gaps.Count)
    }
    elseif ($gaps.Count -gt 0) {
        $steps += ('Review the {0} partial or skipped source(s) in the Coverage section before treating this machine as clean.' -f $gaps.Count)
    }

    if (-not $ScanResult.AllowListFile) {
        $steps += 'No allow-list was supplied, so nothing could be marked Trusted. Create one from Data/allowlist.example.json and rerun with -AllowListPath.'
    }
    $steps += 'File this report with the ticket, then rescan after changes to confirm the result.'
    return $steps
}

function Get-RacReportCss {
    return @'
:root{--bg:#f7f7f5;--paper:#ffffff;--ink:#1d1d1f;--muted:#5f6368;--line:#e3e3df;--soft:#f1f1ee;
--sus:#b42318;--sus-bg:#fdecea;--unk:#a15c07;--unk-bg:#fff4e0;--tru:#05603a;--tru-bg:#e7f6ee;--accent:#1f3a5f;}
@media (prefers-color-scheme: dark){:root{--bg:#121314;--paper:#1b1c1e;--ink:#ececec;--muted:#a1a4a8;--line:#2e3033;--soft:#232528;
--sus:#ff8a80;--sus-bg:#3a1d1b;--unk:#ffc266;--unk-bg:#36290f;--tru:#7bdcab;--tru-bg:#14301f;--accent:#9cc3ff;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
header.mast{border-bottom:3px solid var(--ink);padding-bottom:14px;margin-bottom:22px}
.brand{font:600 12px/1 ui-monospace,"Cascadia Mono",Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
h1{font-size:28px;line-height:1.2;margin:8px 0 12px}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:14px 0 6px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:4px 22px;margin:0;font-size:13px}
.meta div{display:flex;gap:8px}.meta dt{color:var(--muted);min-width:96px}.meta dd{margin:0;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 10px}
.tile{background:var(--paper);border:1px solid var(--line);border-left:6px solid var(--line);border-radius:6px;padding:12px 14px}
.tile .n{font-size:30px;font-weight:700;line-height:1.1}.tile .l{font-size:13px;color:var(--muted)}
.tile.sus{border-left-color:var(--sus)}.tile.sus .n{color:var(--sus)}
.tile.unk{border-left-color:var(--unk)}.tile.unk .n{color:var(--unk)}
.tile.tru{border-left-color:var(--tru)}.tile.tru .n{color:var(--tru)}
.verdict{font-size:16px;margin:6px 0 0}
table{width:100%;border-collapse:collapse;background:var(--paper);font-size:13.5px}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);background:var(--soft)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px}
.badge{display:inline-block;font-size:11.5px;font-weight:700;letter-spacing:.03em;padding:2px 8px;border-radius:999px;white-space:nowrap}
.b-Suspicious{background:var(--sus-bg);color:var(--sus)}.b-Unknown{background:var(--unk-bg);color:var(--unk)}.b-Trusted{background:var(--tru-bg);color:var(--tru)}
.b-Checked{background:var(--tru-bg);color:var(--tru)}.b-Partial,.b-Info{background:var(--soft);color:var(--muted)}
.b-Skipped{background:var(--unk-bg);color:var(--unk)}.b-Error{background:var(--sus-bg);color:var(--sus)}
ol.steps{background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:14px 18px 14px 38px;margin:0}
ol.steps li{margin:4px 0}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
.filters button{font:inherit;font-size:13px;padding:4px 12px;border:1px solid var(--line);background:var(--paper);color:var(--ink);border-radius:999px;cursor:pointer}
.filters button.on{background:var(--ink);color:var(--paper);border-color:var(--ink)}
details.finding{background:var(--paper);border:1px solid var(--line);border-left:5px solid var(--line);border-radius:6px;margin:0 0 10px}
details.finding[data-class=Suspicious]{border-left-color:var(--sus)}
details.finding[data-class=Unknown]{border-left-color:var(--unk)}
details.finding[data-class=Trusted]{border-left-color:var(--tru)}
details.finding>summary{list-style:none;cursor:pointer;padding:10px 14px;display:grid;grid-template-columns:auto auto 1fr;gap:4px 12px;align-items:baseline}
details.finding>summary::-webkit-details-marker{display:none}
.fid{font:600 12.5px ui-monospace,"Cascadia Mono",Consolas,monospace;color:var(--muted)}
.ftitle{font-weight:600;overflow-wrap:anywhere}
.fmeta{grid-column:3;font-size:12.5px;color:var(--muted)}
.fbody{padding:4px 14px 14px;border-top:1px solid var(--line);display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:18px}
table.kv th{width:30%;background:transparent;text-transform:none;letter-spacing:0;font-size:12.5px}
table.kv td{font:12.5px/1.45 ui-monospace,"Cascadia Mono",Consolas,monospace;overflow-wrap:anywhere;word-break:break-word}
ul.reasons{margin:0;padding-left:18px;font-size:13.5px}ul.reasons li{margin:2px 0}
p.rec{margin:0;padding:10px 12px;background:var(--soft);border-radius:6px;font-size:13.5px}
.note{font-size:13px;color:var(--muted)}
footer{margin-top:40px;font-size:12px;color:var(--muted)}
code{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:.92em}
@media (max-width:760px){.fbody{grid-template-columns:1fr}details.finding>summary{grid-template-columns:auto 1fr}.ftitle,.fmeta{grid-column:1 / -1}}
@media print{body{background:#fff;color:#000}.filters{display:none}details.finding{break-inside:avoid}main{max-width:none;padding:0}}
'@
}

function Get-RacReportScript {
    return @'
(function () {
  var buttons = document.querySelectorAll('[data-filter]');
  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      var wanted = button.getAttribute('data-filter');
      document.querySelectorAll('details.finding').forEach(function (d) {
        d.style.display = (wanted === 'All' || d.getAttribute('data-class') === wanted) ? '' : 'none';
      });
      buttons.forEach(function (b) { b.classList.toggle('on', b === button); });
    });
  });
  // Expand every finding when printing so the paper copy is complete.
  window.addEventListener('beforeprint', function () {
    document.querySelectorAll('details').forEach(function (d) { d.setAttribute('open', ''); });
  });
})();
'@
}

function Export-RacFindingHtml {
    param($ScanResult, [string]$Path)

    $findings = @($ScanResult.Findings)
    $s = $ScanResult.Summary
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>Rogue Agent Report - {0} - {1}</title>' -f (ConvertTo-RacHtml $ScanResult.ComputerName), $ScanResult.StartTime.ToString('yyyy-MM-dd HH:mm')))
    [void]$sb.AppendLine('<style>' + (Get-RacReportCss) + '</style></head><body><main>')

    # ---- Masthead -------------------------------------------------------------
    $runAs = ConvertTo-RacHtml $ScanResult.RunAs
    if ($ScanResult.Elevated) { $runAs += ' (elevated)' } else { $runAs += ' (not elevated)' }
    $allow = 'none supplied'
    if ($ScanResult.AllowListFile) { $allow = '{0} &middot; {1} entries &middot; SHA-256 {2}' -f (ConvertTo-RacHtml (Split-Path -Leaf $ScanResult.AllowListFile)), $ScanResult.AllowListEntryCount, (ConvertTo-RacHtml ($ScanResult.AllowListSha256.Substring(0, [math]::Min(16, $ScanResult.AllowListSha256.Length)))) }
    $sigText = '{0} &middot; SHA-256 {1}' -f (ConvertTo-RacHtml $ScanResult.SignatureVersion), (ConvertTo-RacHtml ($ScanResult.SignatureSha256.Substring(0, [math]::Min(16, $ScanResult.SignatureSha256.Length))))
    $duration = [math]::Round(($ScanResult.EndTime - $ScanResult.StartTime).TotalSeconds, 1)

    [void]$sb.AppendLine('<header class="mast"><div class="brand">Rogue Agent Checker &middot; v' + (ConvertTo-RacHtml $ScanResult.ToolVersion) + ' &middot; read-only scan</div>')
    [void]$sb.AppendLine('<h1>AI agent audit: ' + (ConvertTo-RacHtml $ScanResult.ComputerName) + '</h1><dl class="meta">')
    # Build each value first. (Inside @( ), a comma binds tighter than +, so
    # concatenating inline would silently split a value into two array items.)
    $scannedText = (ConvertTo-RacHtml $ScanResult.StartTime.ToString('yyyy-MM-dd HH:mm:ss')) + (' (' + $duration + ' s)')
    $hostText = (ConvertTo-RacHtml $ScanResult.OperatingSystem) + ' &middot; PowerShell ' + (ConvertTo-RacHtml $ScanResult.PowerShellVersion)
    $lookbackText = '{0} days' -f $ScanResult.Parameters.LookbackDays
    $metaRows = @(
        @('Scanned', $scannedText),
        @('Run as', $runAs),
        @('Host', $hostText),
        @('Scan ID', (ConvertTo-RacHtml $ScanResult.ScanId)),
        @('Allow-list', $allow),
        @('Signatures', $sigText),
        @('Lookback', $lookbackText)
    )
    foreach ($pair in $metaRows) {
        [void]$sb.AppendLine(('<div><dt>{0}</dt><dd>{1}</dd></div>' -f $pair[0], $pair[1]))
    }
    [void]$sb.AppendLine('</dl></header>')

    # ---- Summary ------------------------------------------------------------------
    [void]$sb.AppendLine('<section><div class="tiles">')
    [void]$sb.AppendLine(('<div class="tile sus"><div class="n">{0}</div><div class="l">Suspicious</div></div>' -f $s.Suspicious))
    [void]$sb.AppendLine(('<div class="tile unk"><div class="n">{0}</div><div class="l">Unknown (not approved)</div></div>' -f $s.Unknown))
    [void]$sb.AppendLine(('<div class="tile tru"><div class="n">{0}</div><div class="l">Trusted (on allow-list)</div></div>' -f $s.Trusted))
    [void]$sb.AppendLine(('<div class="tile"><div class="n">{0}</div><div class="l">Distinct agents</div></div>' -f $s.Agents))
    [void]$sb.AppendLine('</div>')
    if ($s.Suspicious -gt 0) { $verdict = '{0} suspicious finding(s) need attention now. {1} unknown item(s) need an owner decision.' -f $s.Suspicious, $s.Unknown }
    elseif ($s.Unknown -gt 0) { $verdict = 'Nothing suspicious, but {0} item(s) are not on the allow-list and need an owner decision.' -f $s.Unknown }
    elseif ($s.Total -gt 0) { $verdict = 'Every AI agent found is on the allow-list.' }
    else { $verdict = 'No AI agent breadcrumbs were found in the sources that could be examined. Check Coverage before calling this machine clean.' }
    [void]$sb.AppendLine('<p class="verdict">' + (ConvertTo-RacHtml $verdict) + '</p></section>')

    # ---- What to do next -----------------------------------------------------------
    [void]$sb.AppendLine('<section><h2>What to do next</h2><ol class="steps">')
    foreach ($step in (Get-RacNextStep -ScanResult $ScanResult)) { [void]$sb.AppendLine('<li>' + (ConvertTo-RacHtml $step) + '</li>') }
    [void]$sb.AppendLine('</ol></section>')

    # ---- Agents ---------------------------------------------------------------------
    [void]$sb.AppendLine('<section><h2>Agents on this machine</h2><div class="wrap"><table><thead><tr><th>Agent</th><th>Status</th><th>Findings</th><th>Categories</th><th>Users</th></tr></thead><tbody>')
    $agentGroups = $findings | Group-Object -Property Agent | Sort-Object @{ Expression = { ($_.Group | ForEach-Object { Get-RacClassRank $_.Classification } | Measure-Object -Minimum).Minimum } }, @{ Expression = { $_.Count }; Descending = $true }
    foreach ($g in $agentGroups) {
        $worst = ($g.Group | Sort-Object { Get-RacClassRank $_.Classification } | Select-Object -First 1).Classification
        $cats = @($g.Group | ForEach-Object { $script:RacCategoryLabels[$_.Category] } | Select-Object -Unique | Sort-Object) -join ', '
        # One name per person: 'bob' and 'CORP\bob' are shown once, preferring the domain form.
        $byLeaf = [ordered]@{}
        foreach ($u in @($g.Group | ForEach-Object { ([string]$_.User) -split ',\s*' } | Where-Object { $_ })) {
            $leaf = (Get-RacUserLeaf $u).ToLowerInvariant()
            if (-not $byLeaf.Contains($leaf) -or $u.Length -gt $byLeaf[$leaf].Length) { $byLeaf[$leaf] = $u }
        }
        $users = @($byLeaf.Values) -join ', '
        [void]$sb.AppendLine(('<tr><td><strong>{0}</strong></td><td><span class="badge b-{1}">{1}</span></td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-RacHtml $g.Name), $worst, $g.Count, (ConvertTo-RacHtml $cats), (ConvertTo-RacHtml $users)))
    }
    if (@($agentGroups).Count -eq 0) { [void]$sb.AppendLine('<tr><td colspan="5" class="note">None found.</td></tr>') }
    [void]$sb.AppendLine('</tbody></table></div></section>')

    # ---- Findings -----------------------------------------------------------------
    [void]$sb.AppendLine('<section><h2>Findings</h2>')
    [void]$sb.AppendLine(('<div class="filters"><button class="on" data-filter="All">All ({0})</button><button data-filter="Suspicious">Suspicious ({1})</button><button data-filter="Unknown">Unknown ({2})</button><button data-filter="Trusted">Trusted ({3})</button></div>' -f $s.Total, $s.Suspicious, $s.Unknown, $s.Trusted))
    foreach ($f in $findings) {
        $open = ''
        if ($f.Classification -eq 'Suspicious') { $open = ' open' }
        $when = ''
        if ($f.EventTime -is [datetime]) { $when = ' &middot; ' + (ConvertTo-RacHtml $f.EventTime) }
        $userText = ''
        if ($f.User) { $userText = ' &middot; ' + (ConvertTo-RacHtml $f.User) }
        [void]$sb.AppendLine(('<details class="finding" data-class="{0}"{1}><summary>' -f $f.Classification, $open))
        [void]$sb.AppendLine(('<span class="badge b-{0}">{0}</span><span class="fid">{1}</span><span class="ftitle">{2}</span>' -f $f.Classification, (ConvertTo-RacHtml $f.FindingId), (ConvertTo-RacHtml $f.Title)))
        [void]$sb.AppendLine(('<span class="fmeta">{0} &middot; {1} &middot; {2}{3}{4} &middot; score {5}</span></summary>' -f (ConvertTo-RacHtml $script:RacCategoryLabels[$f.Category]), (ConvertTo-RacHtml $f.Breadcrumb), (ConvertTo-RacHtml $f.Agent), $userText, $when, $f.Score))
        [void]$sb.AppendLine('<div class="fbody"><div><h3>Evidence</h3><table class="kv"><tbody>')
        [void]$sb.AppendLine(('<tr><th>Location</th><td>{0}</td></tr>' -f (ConvertTo-RacHtml $f.Location)))
        foreach ($k in $f.Evidence.Keys) {
            [void]$sb.AppendLine(('<tr><th>{0}</th><td>{1}</td></tr>' -f (ConvertTo-RacHtml $k), (ConvertTo-RacHtml $f.Evidence[$k])))
        }
        [void]$sb.AppendLine('</tbody></table></div><div><h3>Why this label</h3><ul class="reasons">')
        foreach ($r in @($f.Reasons)) { [void]$sb.AppendLine('<li>' + (ConvertTo-RacHtml $r) + '</li>') }
        [void]$sb.AppendLine('</ul><h3>Recommended next step</h3><p class="rec">' + (ConvertTo-RacHtml $f.Recommendation) + '</p></div></div></details>')
    }
    if ($findings.Count -eq 0) { [void]$sb.AppendLine('<p class="note">No findings.</p>') }
    [void]$sb.AppendLine('</section>')

    # ---- Coverage -----------------------------------------------------------------
    [void]$sb.AppendLine('<section><h2>Coverage</h2><p class="note">What this scan could and could not examine. "Nothing found" only means something for sources marked Checked.</p>')
    [void]$sb.AppendLine('<div class="wrap"><table><thead><tr><th>Source</th><th>Status</th><th>Items</th><th>Detail</th></tr></thead><tbody>')
    foreach ($c in @($ScanResult.Coverage)) {
        $items = ''
        if ($c.ItemCount -ge 0) { $items = [string]$c.ItemCount }
        [void]$sb.AppendLine(('<tr><td>{0}</td><td><span class="badge b-{1}">{1}</span></td><td>{2}</td><td>{3}</td></tr>' -f (ConvertTo-RacHtml $c.Source), $c.Status, $items, (ConvertTo-RacHtml $c.Detail)))
    }
    [void]$sb.AppendLine('</tbody></table></div>')
    if (@($ScanResult.AllowListWarnings).Count -gt 0) {
        [void]$sb.AppendLine('<h3>Allow-list warnings</h3><ul class="reasons">')
        foreach ($w in $ScanResult.AllowListWarnings) { [void]$sb.AppendLine('<li>' + (ConvertTo-RacHtml $w) + '</li>') }
        [void]$sb.AppendLine('</ul>')
    }
    [void]$sb.AppendLine('</section>')

    # ---- Method ---------------------------------------------------------------------
    $threshold = $ScanResult.Threshold
    [void]$sb.AppendLine('<section><h2>Method and safety</h2><ul class="reasons">')
    foreach ($line in @(
            'Read-only: the scan queried processes, network tables, the DNS cache, the registry, Task Scheduler, services, WMI, event logs and files. It changed nothing.',
            'Local-only: no network requests or DNS lookups were made. Hostnames come from the local DNS cache.',
            'Secrets: API keys are detected by name and format. Their values were never recorded; command lines and snippets are redacted.',
            ('Classification: each finding scores the sum of its indicator weights. Approved (allow-listed) findings stay Trusted unless risk the approval does not accept reaches {0}. Unapproved findings are Unknown, or Suspicious at {0} or more.' -f $threshold),
            ('Files written: ' + (@($ScanResult.ReportFiles.Values | ForEach-Object { Split-Path -Leaf $_ }) -join ', '))
        )) {
        [void]$sb.AppendLine('<li>' + (ConvertTo-RacHtml $line) + '</li>')
    }
    [void]$sb.AppendLine('</ul></section>')

    [void]$sb.AppendLine('<footer>Generated by Rogue Agent Checker v' + (ConvertTo-RacHtml $ScanResult.ToolVersion) + ' on ' + (ConvertTo-RacHtml $ScanResult.ComputerName) + '. Report only: nothing was disabled, blocked or deleted.</footer>')
    [void]$sb.AppendLine('</main><script>' + (Get-RacReportScript) + '</script></body></html>')

    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}
