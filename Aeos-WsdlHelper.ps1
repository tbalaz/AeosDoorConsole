<#
.SYNOPSIS
    Read-only: lists the operations of the AEOS SOAP web service whose names match a pattern, each with its
    request element and fields, straight from the WSDL. Use it to find which operation to map to List doors,
    Lock, Unlock and Provide access in Aeos-DoorConsole.ps1.
.DESCRIPTION
    Reads <AeosUrl>?wsdl (or -WsdlUrl) and every XSD / WSDL it imports. For each operation whose name matches
    -Match it prints the request element, its fields (name : type, optional / list), nested fields down to
    -Depth levels, and the allowed values of fields with a fixed value list (for example a mode or state).
    It sends no SOAP request and changes nothing. The output is also saved next to this script as
    aeos-wsdl-<time>.txt - send that file back when asking for help.
    Windows PowerShell 5.1.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Aeos-WsdlHelper.ps1 -AeosUrl https://aeos-server:8443/aeosws -SkipTlsCheck
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Aeos-WsdlHelper.ps1 -AeosUrl https://aeos-server:8443/aeosws -SkipTlsCheck -Match entrance -AskCredential
    (-Match '.' lists every operation; -AskCredential when the WSDL needs the AEOS login)
#>
param(
    [Parameter(Mandatory = $true)][string]$AeosUrl,                 # the AEOS web service URL, as on the Setup tab
    [string]$WsdlUrl = '',                                          # empty = AeosUrl + ?wsdl
    [string]$Match = 'accesspoint|entrance|door|lock|release|block|open|mode|state|status',   # regex on operation names
    [int]$Depth = 2,                                                # how many levels of nested fields to show
    [switch]$SkipTlsCheck,                                          # self-signed AEOS certificate (this run only)
    [switch]$AskCredential,                                         # ask for the AEOS user if the WSDL needs a login
    [pscredential]$Credential                                       # or pass one (when called from a PowerShell session)
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($SkipTlsCheck) { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
$script:Cred = $Credential
if ($AskCredential) { $script:Cred = Get-Credential -Message 'AEOS user' }
if (-not $WsdlUrl) { $WsdlUrl = $AeosUrl.TrimEnd('/') + '?wsdl' }

function Get-Xml([string]$Url) {
    $p = @{ Uri = $Url; UseBasicParsing = $true }
    if ($script:Cred) {
        # HTTP Basic sent up front (PowerShell 5.1 -Credential only answers a challenge). Kept in memory only.
        $nc = $script:Cred.GetNetworkCredential()
        $p.Headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($nc.UserName + ':' + $nc.Password)) }
    }
    try {
        $c = (Invoke-WebRequest @p).Content
        if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }   # served without a text content type
        [xml]([string]$c).TrimStart([char]0xFEFF)
    }
    catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        if ($code -eq 401) { throw "$Url answered 401 Unauthorized - run again with -AskCredential and the AEOS user." }
        throw "$Url could not be read: $($_.Exception.Message)$(if(-not $SkipTlsCheck){' (self-signed AEOS certificate? add -SkipTlsCheck)'})"
    }
}
function Get-LocalName([string]$Q) { if ($Q) { $Q -replace '^.*:', '' } else { '' } }
function Test-BuiltinType([string]$Q) { $Q -match '^(xs|xsd|s|xsi):' }

# All schema documents: the WSDL plus everything it imports or includes (max 30 files).
$script:Docs = New-Object System.Collections.Generic.List[xml]
$script:Seen = @{}
function Add-Imports([xml]$Doc, [string]$BaseUrl) {
    foreach ($n in @($Doc.SelectNodes("//*[local-name()='import' or local-name()='include']"))) {
        $loc = $n.GetAttribute('schemaLocation'); if (-not $loc) { $loc = $n.GetAttribute('location') }
        if (-not $loc) { continue }
        $abs = ([uri]::new([uri]$BaseUrl, $loc)).AbsoluteUri
        if ($script:Seen.ContainsKey($abs) -or $script:Seen.Count -ge 30) { continue }
        $script:Seen[$abs] = $true
        try { $d = Get-Xml $abs; $script:Docs.Add($d); Add-Imports $d $abs }
        catch { "  (could not read imported file $abs : $($_.Exception.Message))" }
    }
}
function Find-Node([string]$Kind, [string]$Name) {
    foreach ($d in $script:Docs) { $n = $d.SelectSingleNode("//*[local-name()='$Kind' and @name='$Name']"); if ($n) { return $n } }
    $null
}
# Fields declared directly in an element / complexType (a base type's fields first), nested ones indented.
function Show-Type([System.Xml.XmlNode]$Node, [string]$Indent, [int]$Level) {
    $ext = $Node.SelectSingleNode(".//*[local-name()='extension'][@base]")
    if ($ext -and -not (Test-BuiltinType $ext.GetAttribute('base'))) {
        $b = Get-LocalName $ext.GetAttribute('base'); $bn = Find-Node 'complexType' $b
        if ($bn) { "$Indent(fields of base type $b)"; Show-Type $bn $Indent $Level }
    }
    foreach ($e in @($Node.SelectNodes(".//*[local-name()='element']"))) {
        $p = $e.ParentNode; $nested = $false
        while ($p -and -not [object]::ReferenceEquals($p, $Node)) { if ($p.LocalName -eq 'element') { $nested = $true; break }; $p = $p.ParentNode }
        if ($nested) { continue }
        $name = $e.GetAttribute('name'); $ref = $e.GetAttribute('ref'); $type = $e.GetAttribute('type')
        if (-not $name -and $ref) { $name = Get-LocalName $ref }
        $flags = ''
        if ($e.GetAttribute('minOccurs') -eq '0') { $flags += ' (optional)' }
        if ($e.GetAttribute('maxOccurs') -and $e.GetAttribute('maxOccurs') -ne '1') { $flags += ' (list)' }
        $shown = if ($type) { $type } elseif ($ref) { 'ref ' + $ref } else { '(inline type)' }
        "$Indent$name : $shown$flags"
        $simple = $null
        if ($type -and -not (Test-BuiltinType $type)) { $simple = Find-Node 'simpleType' (Get-LocalName $type) }
        if (-not $simple) { $simple = $e.SelectSingleNode("./*[local-name()='simpleType']") }
        if ($simple) {
            $vals = @($simple.SelectNodes(".//*[local-name()='enumeration']") | ForEach-Object { $_.GetAttribute('value') })
            if ($vals.Count) { "$Indent    allowed values: $($vals -join ', ')" }
        }
        if ($Level -lt $Depth) {
            $sub = $null
            if ($type -and -not (Test-BuiltinType $type)) { $sub = Find-Node 'complexType' (Get-LocalName $type) }
            elseif ($ref) { $sub = Find-Node 'element' (Get-LocalName $ref) }
            elseif (-not $type -and $e.SelectSingleNode("./*[local-name()='complexType']")) { $sub = $e }
            if ($sub -and -not [object]::ReferenceEquals($sub, $Node)) { Show-Type $sub ($Indent + '    ') ($Level + 1) }
        }
    }
}
function Show-Element([string]$Name, [string]$Indent) {
    $el = Find-Node 'element' $Name
    if (-not $el) { $el = Find-Node 'complexType' $Name }
    if (-not $el) { "$Indent(element $Name not found in the WSDL or its imports)"; return }
    $t = $el.GetAttribute('type')
    if ($t -and -not (Test-BuiltinType $t)) { $ct = Find-Node 'complexType' (Get-LocalName $t); if ($ct) { "$Indent(type $(Get-LocalName $t))"; Show-Type $ct $Indent 1; return } }
    Show-Type $el $Indent 1
}

$main = {
    "AEOS WSDL helper - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $WsdlUrl"
    $wsdl = Get-Xml $WsdlUrl
    $script:Docs.Add($wsdl)
    Add-Imports $wsdl $WsdlUrl
    $tns = $wsdl.DocumentElement.GetAttribute('targetNamespace')
    $all = @{}
    foreach ($op in @($wsdl.SelectNodes("//*[local-name()='portType']/*[local-name()='operation']"))) { $all[$op.GetAttribute('name')] = $op }
    $names = @($all.Keys | Where-Object { $_ -match $Match } | Sort-Object)
    "Target namespace: $tns - $($all.Count) operations, $($names.Count) match '$Match', files read: $($script:Docs.Count)"
    ''
    foreach ($n in $names) {
        $op = $all[$n]
        "=== $n"
        $in = $op.SelectSingleNode("./*[local-name()='input']")
        if (-not $in) { '    (no request message)'; continue }
        $msg = Find-Node 'message' (Get-LocalName $in.GetAttribute('message'))
        if (-not $msg) { "    (request message $($in.GetAttribute('message')) not found)"; continue }
        foreach ($part in @($msg.SelectNodes("./*[local-name()='part']"))) {
            $pe = $part.GetAttribute('element'); $pt = $part.GetAttribute('type')
            if ($pe) { "    request element: $(Get-LocalName $pe)"; Show-Element (Get-LocalName $pe) '        ' }
            elseif ($pt) {
                "    request part $($part.GetAttribute('name')) : $pt"
                if (-not (Test-BuiltinType $pt)) { $ct = Find-Node 'complexType' (Get-LocalName $pt); if ($ct) { Show-Type $ct '        ' 1 } }
            }
        }
        ''
    }
}
$out = @(& $main)
$out
$file = Join-Path $PSScriptRoot ('aeos-wsdl-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
try { Set-Content -LiteralPath $file -Value $out -Encoding UTF8; "Saved to $file" } catch { "Not saved: $($_.Exception.Message)" }
