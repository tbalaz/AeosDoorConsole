<#
.SYNOPSIS
    READ-ONLY check of the classic maps in a Milestone XProtect system (what DoorKeeper could import).

.DESCRIPTION
    Logs in to the XProtect management server (Windows login of the current user, or -Credential), then only READS:
    the classic maps (building pictures and floor plans), the hot zones that link a map to another map, and the
    items placed on each map (cameras, hot zones, other items such as access control doors). Prints a tree
    (building picture -> floor plans) and a summary. Also counts cameras that have a Smart Map position (a hint
    that Smart Map is used as well). Nothing is changed on the server.

    Floor plans are sensitive: images are saved only with -SaveImages <folder>, and only into that folder.
    The maps part of the REST API is not documented by Milestone (it works in the XProtect REST API Gateway); item
    type ids come from Milestone's own client code. Unknown item types are listed with sample names.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Xprotect-MapCheck.ps1 -ManagementServer ms01.example.local
    powershell -ExecutionPolicy Bypass -File .\Xprotect-MapCheck.ps1 -ManagementServer ms01 -Credential (Get-Credential) -SaveImages C:\temp\maps -SkipCertCheck
#>
param(
    [Parameter(Mandatory = $true)][string]$ManagementServer,
    [System.Management.Automation.PSCredential]$Credential = $null,
    [string]$SaveImages = '',
    [switch]$SkipCertCheck,
    [string]$Out = ''
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($SkipCertCheck) { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
$base = 'https://' + $ManagementServer
$lines = New-Object System.Collections.Generic.List[string]
function Say([string]$t) { Write-Host $t; $lines.Add($t) }
$TYPES = @{ 'da39f4ca-20fc-48ab-82cf-8508bbb7e67a' = 'map'; 'b1e26e7d-2d8e-4ad0-93b1-7d19430d0e2c' = 'camera'; 'fb908a91-c777-4b52-8ebc-b529b44093c4' = 'hotzone' }

function Get-SafeImagePath {
    # Server values never steer the path: the map id must be a GUID, the name is reduced to letters, digits, space,
    # '_' and '-' (no dots, no slashes), and the full path must stay inside the folder. Returns $null when unsafe.
    param([string]$Folder, [string]$MapName, [string]$MapId, [string]$Ext)
    $g = [guid]::Empty
    if (-not [guid]::TryParse($MapId, [ref]$g)) { return $null }
    if (@('.jpg', '.png', '.bin') -notcontains $Ext) { return $null }
    $safe = ($MapName -replace '[^A-Za-z0-9 _-]', '_')
    if ($safe.Length -gt 60) { $safe = $safe.Substring(0, 60) }
    $dir = [IO.Path]::GetFullPath($Folder).TrimEnd('\') + '\'
    $target = [IO.Path]::GetFullPath((Join-Path $dir ($safe + '_' + $g.ToString() + $Ext)))
    if (-not $target.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    return $target
}

# Login: IDP token with the Windows login (NTLM / Kerberos), read-only from here on.
$tokArgs = @{ Method = 'Post'; Uri = ($base + '/IDP/connect/token'); ContentType = 'application/x-www-form-urlencoded'
    Body = 'grant_type=windows_credentials&client_id=GrantValidatorClient' }
if ($Credential) { $tokArgs['Credential'] = $Credential } else { $tokArgs['UseDefaultCredentials'] = $true }
try { $tok = (Invoke-RestMethod @tokArgs).access_token }
catch { Write-Host ('LOGIN FAILED at ' + $base + '/IDP/connect/token: ' + $_.Exception.Message); exit 1 }
$hdr = @{ Authorization = ('Bearer ' + $tok) }

function Get-Api([string]$Path) {
    try { return Invoke-RestMethod -Uri ($base + '/api/rest/v1/' + $Path) -Headers $hdr -TimeoutSec 120 }
    catch { $code = 0; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode.value__ }; return [pscustomobject]@{ __error = $code; __msg = $_.Exception.Message } }
}
function Get-Items($Resp) {
    if ($null -ne $Resp.array) { return @($Resp.array) }
    if ($null -ne $Resp.data) { return @($Resp.data) }
    return @()
}

Say ('XProtect map check - ' + $ManagementServer + ' - ' + (Get-Date -Format 'yyyy-MM-dd HH:mm'))
$r = Get-Api 'maps?size=500'
if ($r.__error) { Say ('Classic maps: the maps resource answered HTTP ' + $r.__error + ' (' + $r.__msg + ')'); $maps = @() }
else { $maps = Get-Items $r }
Say ('Classic maps: ' + $maps.Count)

$info = @{}
$typeCount = @{}
$other = @{}
foreach ($m in $maps) {
    $id = $m.relations.self.id
    $d = Get-Api ('maps/' + $id + '?include=displayXml')
    $dx = ''; if (-not $d.__error) { $dm = $d; if ($d.data) { $dm = $d.data }; $dx = [string]$dm.displayXml }
    $img = [regex]::Match($dx, '<(\w*[Ii]mage\w*)>([A-Za-z0-9+/=\s]{200,})</')
    $imgNote = 'no image found'
    if ($img.Success) {
        $bytes = [Convert]::FromBase64String(($img.Groups[2].Value -replace '\s', ''))
        $kind = 'unknown format'
        if ($bytes.Length -gt 3 -and $bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50) { $kind = 'PNG' } elseif ($bytes.Length -gt 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8) { $kind = 'JPG' }
        $imgNote = $kind + ' ' + [Math]::Round($bytes.Length / 1KB) + ' KB'
        if ($SaveImages) {
            if (-not (Test-Path $SaveImages)) { New-Item -ItemType Directory -Path $SaveImages | Out-Null }
            $ext = if ($kind -eq 'JPG') { '.jpg' } elseif ($kind -eq 'PNG') { '.png' } else { '.bin' }
            $target = Get-SafeImagePath -Folder $SaveImages -MapName ([string]$m.name) -MapId ([string]$id) -Ext $ext
            if ($target) { [IO.File]::WriteAllBytes($target, $bytes) }
            else { Say ('  image not saved: unsafe map id or path (' + $m.name + ')') }
        }
    }
    $vi = Get-Api ('maps/' + $id + '/visualItems?size=1000')
    $items = @(); if (-not $vi.__error) { $items = Get-Items $vi }
    $links = @(); $cnt = @{}
    foreach ($v in $items) {
        $tg = [string]$v.relations.self.type
        $t = $TYPES[$tg.ToLowerInvariant()]; if (-not $t) { $t = 'other:' + $tg }
        $cnt[$t] = 1 + [int]$cnt[$t]; $typeCount[$t] = 1 + [int]$typeCount[$t]
        if ($t -eq 'hotzone' -and $v.relations.related) { $links += [string]$v.relations.related.id }
        if ($t -like 'other:*') { if (-not $other[$t]) { $other[$t] = New-Object System.Collections.Generic.List[string] }; if ($other[$t].Count -lt 5) { $other[$t].Add([string]$v.name) } }
    }
    $info[$id] = [pscustomobject]@{ Name = $m.name; Image = $imgNote; Counts = $cnt; Links = $links; ItemsError = $vi.__error }
}

# Tree: maps no hot zone points to are the top (building pictures); hot zones lead to the floor plans.
$linked = @{}; foreach ($k in $info.Keys) { foreach ($l in $info[$k].Links) { $linked[$l] = $true } }
function Show-Map([string]$Id, [int]$Depth, [hashtable]$Seen) {
    $x = $info[$Id]; if (-not $x) { Say ((' ' * $Depth * 2) + '-> (map ' + $Id + ' not readable)'); return }
    $c = ($x.Counts.Keys | Sort-Object | ForEach-Object { $_ + '=' + $x.Counts[$_] }) -join ', '
    Say ((' ' * $Depth * 2) + '- ' + $x.Name + '  [' + $x.Image + ']  items: ' + $(if ($c) { $c } else { 'none' }) + $(if ($x.ItemsError) { ' (items HTTP ' + $x.ItemsError + ')' } else { '' }))
    if ($Seen[$Id]) { return }; $Seen[$Id] = $true
    foreach ($l in $x.Links) { Show-Map $l ($Depth + 1) $Seen }
}
if ($maps.Count -gt 0) {
    Say ''; Say 'Map tree (building picture -> floor plans via hot zones):'
    $seen = @{}
    foreach ($k in $info.Keys) { if (-not $linked[$k]) { Show-Map $k 1 $seen } }
    foreach ($k in $info.Keys) { if (-not $seen[$k]) { Show-Map $k 1 $seen } }
    Say ''; Say 'Item types on all maps:'
    foreach ($t in ($typeCount.Keys | Sort-Object)) { Say ('  ' + $t + ': ' + $typeCount[$t] + $(if ($other[$t]) { '  e.g. ' + ($other[$t] -join ' | ') } else { '' })) }
    if ($other.Count -gt 0) { Say '  ("other" types are not cameras, maps or hot zones - access control doors would show up here.)' }
}

# Smart Map hint: cameras with a map position.
$cams = Get-Api 'cameras?size=5000'
if ($cams.__error) { Say ''; Say ('Cameras: HTTP ' + $cams.__error) }
else {
    $all = Get-Items $cams
    $pos = @($all | Where-Object { $_.gisPoint -and [string]$_.gisPoint -notmatch 'EMPTY' }).Count
    Say ''; Say ('Cameras: ' + $all.Count + ', with a Smart Map position: ' + $pos + $(if ($pos -gt 0) { '  (Smart Map is used for these)' } else { '' }))
}
if ($SaveImages) { Say ('Images saved to: ' + $SaveImages) }
if ($Out) { [IO.File]::WriteAllLines($Out, $lines) ; Write-Host ('Report: ' + $Out) }
