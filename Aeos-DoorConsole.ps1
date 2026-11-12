<#
.SYNOPSIS
    AEOS Door Console - local web page that forwards calls to a Nedap AEOS SOAP web service.

.DESCRIPTION
    Single self-contained Windows PowerShell 5.1 script. Serves http://localhost:<Port>/ (HttpListener,
    localhost only) with an embedded page (no CDN, works offline). Lists doors and offers lock / unlock /
    provide access per door. No AEOS operation names are built in: the operator maps each action to a WSDL
    operation and a request template on the Setup tab.

    Security: per-start random token (meta tag, header X-Console-Token on /api/v1/*), Origin check,
    AEOS password kept in memory only (PSCredential), never logged or written. Certificate validation
    can be skipped per request only (compiled callback), never globally. Every door action is written to
    a hash-chained audit file. A thorough debug log (aeos-console-debug.log) is always on.

.PARAMETER ConfigFile
    Site config. Default: aeos-console.json next to the script (created from cleared defaults if missing).

.PARAMETER Port
    Local port. Default 8765.

.PARAMETER NoBrowser
    Do not open the default browser.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Aeos-DoorConsole.ps1
    powershell -ExecutionPolicy Bypass -File .\Aeos-DoorConsole.ps1 -Port 9000 -NoBrowser
#>
[CmdletBinding()]
param(
    [string]$ConfigFile = '',
    [int]$Port = 8765,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$script:Version = '1.0.0'
$script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:ZeroHash = ('0' * 64)
$script:ActionNames = @('listDoors', 'lock', 'unlock', 'access')

# ============================================================================
# Pure helpers (no script state; unit tested through tests\Test-Unit.ps1)
# ============================================================================

function ConvertTo-XmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&apos;')
}

function Expand-Template {
    # Single-pass replacement of {{id}} {{name}} {{ns}} {{tns}}; id/name/tns are XML-escaped.
    param([string]$Body, [string]$Id, [string]$Name, [string]$Ns, [string]$Tns)
    if ($null -eq $Body) { return '' }
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        switch ($m.Groups[1].Value) {
            'id' { return (ConvertTo-XmlEscaped $Id) }
            'name' { return (ConvertTo-XmlEscaped $Name) }
            'ns' { return $Ns }
            'tns' { return (ConvertTo-XmlEscaped $Tns) }
        }
        return $m.Value
    }
    return [System.Text.RegularExpressions.Regex]::Replace($Body, '\{\{(id|name|ns|tns)\}\}', $evaluator)
}

function New-SoapEnvelope {
    param(
        [string]$Body,
        [string]$SoapVersion = '1.1',
        [string]$Auth = 'basic',
        [string]$User = '',
        [string]$Password = '',
        [string]$Ns = 'aeos',
        [string]$Tns = ''
    )
    $envNs = 'http://schemas.xmlsoap.org/soap/envelope/'
    if ($SoapVersion -eq '1.2') { $envNs = 'http://www.w3.org/2003/05/soap-envelope' }
    $nsAttr = ''
    if ($Tns) { $nsAttr = ' xmlns:' + $Ns + '="' + (ConvertTo-XmlEscaped $Tns) + '"' }
    $header = ''
    if ($Auth -eq 'wsse') {
        $secNs = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
        $pwType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'
        $header = '<wsse:Security xmlns:wsse="' + $secNs + '" soapenv:mustUnderstand="1"><wsse:UsernameToken><wsse:Username>' +
            (ConvertTo-XmlEscaped $User) + '</wsse:Username><wsse:Password Type="' + $pwType + '">' +
            (ConvertTo-XmlEscaped $Password) + '</wsse:Password></wsse:UsernameToken></wsse:Security>'
    }
    return '<soapenv:Envelope xmlns:soapenv="' + $envNs + '"' + $nsAttr + '><soapenv:Header>' + $header +
        '</soapenv:Header><soapenv:Body>' + $Body + '</soapenv:Body></soapenv:Envelope>'
}

function Get-SoapRequestHeaders {
    param([string]$SoapVersion = '1.1', [string]$SoapAction = '')
    if ($SoapVersion -eq '1.2') {
        $ct = 'application/soap+xml; charset=utf-8'
        if ($SoapAction) { $ct = $ct + '; action="' + $SoapAction + '"' }
        return [pscustomobject]@{ ContentType = $ct; SoapActionHeader = '' }
    }
    return [pscustomobject]@{ ContentType = 'text/xml; charset=utf-8'; SoapActionHeader = ('"' + $SoapAction + '"') }
}

function ConvertTo-XmlDocument {
    param([string]$Text)
    if ($null -eq $Text) { throw 'Empty XML text.' }
    $clean = $Text.TrimStart([char]0xFEFF).Trim()
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $sr = New-Object System.IO.StringReader($clean)
    $xr = [System.Xml.XmlReader]::Create($sr, $settings)
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($xr)
        return , $doc
    }
    finally {
        $xr.Close()
        $sr.Close()
    }
}

function Get-XmlParseError {
    # $null when the text is well-formed XML, else the parser message.
    param([string]$Text)
    try { [void](ConvertTo-XmlDocument $Text); return $null }
    catch { return $_.Exception.Message }
}

function Format-XmlPretty {
    param([string]$Text)
    try {
        $doc = ConvertTo-XmlDocument $Text
        $sw = New-Object System.IO.StringWriter
        $st = New-Object System.Xml.XmlWriterSettings
        $st.Indent = $true
        $st.IndentChars = '  '
        $st.OmitXmlDeclaration = $true
        $xw = [System.Xml.XmlWriter]::Create($sw, $st)
        $doc.Save($xw)
        $xw.Close()
        return $sw.ToString()
    }
    catch { return $Text }
}

function Read-WsdlInfo {
    # Parses a WSDL 1.1 document: target namespace, SOAP version, operations (name, soapAction, input element).
    param([string]$Text)
    $doc = ConvertTo-XmlDocument $Text
    $root = $doc.DocumentElement
    if ($root.LocalName -ne 'definitions') {
        throw ('Not a WSDL 1.1 document (root element is "' + $root.LocalName + '").')
    }
    $tns = $root.GetAttribute('targetNamespace')
    $msgElem = @{}
    $ptOps = New-Object System.Collections.ArrayList
    $bindOps = New-Object System.Collections.ArrayList
    $soapAction = @{}
    $has11 = $false
    $has12 = $false
    foreach ($n in $root.ChildNodes) {
        if ($n.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if ($n.LocalName -eq 'message') {
            $el = ''
            foreach ($p in $n.ChildNodes) {
                if ($p.NodeType -eq [System.Xml.XmlNodeType]::Element -and $p.LocalName -eq 'part') {
                    $e = $p.GetAttribute('element')
                    if ($e) { $el = ($e -split ':')[-1]; break }
                }
            }
            $msgElem[$n.GetAttribute('name')] = $el
        }
        elseif ($n.LocalName -eq 'portType') {
            foreach ($o in $n.ChildNodes) {
                if ($o.NodeType -ne [System.Xml.XmlNodeType]::Element -or $o.LocalName -ne 'operation') { continue }
                $inMsg = ''
                foreach ($c in $o.ChildNodes) {
                    if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element -and $c.LocalName -eq 'input') {
                        $inMsg = ($c.GetAttribute('message') -split ':')[-1]
                    }
                }
                [void]$ptOps.Add([pscustomobject]@{ Name = $o.GetAttribute('name'); Message = $inMsg })
            }
        }
        elseif ($n.LocalName -eq 'binding') {
            foreach ($o in $n.ChildNodes) {
                if ($o.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                if ($o.LocalName -eq 'binding') {
                    if ($o.NamespaceURI -eq 'http://schemas.xmlsoap.org/wsdl/soap12/') { $has12 = $true }
                    elseif ($o.NamespaceURI -eq 'http://schemas.xmlsoap.org/wsdl/soap/') { $has11 = $true }
                }
                elseif ($o.LocalName -eq 'operation') {
                    $oname = $o.GetAttribute('name')
                    [void]$bindOps.Add($oname)
                    foreach ($c in $o.ChildNodes) {
                        if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element -and $c.LocalName -eq 'operation') {
                            if (-not $soapAction.ContainsKey($oname)) { $soapAction[$oname] = $c.GetAttribute('soapAction') }
                        }
                    }
                }
            }
        }
    }
    $ops = New-Object System.Collections.ArrayList
    $seen = @{}
    $names = New-Object System.Collections.ArrayList
    foreach ($p in $ptOps) { if (-not $seen.ContainsKey($p.Name)) { $seen[$p.Name] = $true; [void]$names.Add($p) } }
    if ($names.Count -eq 0) {
        foreach ($b in $bindOps) { if (-not $seen.ContainsKey($b)) { $seen[$b] = $true; [void]$names.Add([pscustomobject]@{ Name = $b; Message = '' }) } }
    }
    foreach ($p in $names) {
        $elem = ''
        if ($p.Message -and $msgElem.ContainsKey($p.Message)) { $elem = $msgElem[$p.Message] }
        if (-not $elem) { $elem = $p.Name }
        $sa = ''
        if ($soapAction.ContainsKey($p.Name)) { $sa = $soapAction[$p.Name] }
        [void]$ops.Add([pscustomobject]@{
                name         = $p.Name
                soapAction   = $sa
                inputElement = $elem
                skeleton     = ('<{{ns}}:' + $elem + '></{{ns}}:' + $elem + '>')
            })
    }
    $ver = '1.1'
    if ($has12 -and -not $has11) { $ver = '1.2' }
    return [pscustomobject]@{ targetNamespace = $tns; soapVersion = $ver; operations = @($ops.ToArray()) }
}

function Get-FirstDescendantText {
    param($Node, [string]$LocalName)
    if (-not $LocalName) { return '' }
    foreach ($d in $Node.SelectNodes('.//*')) {
        if ($d.LocalName -ceq $LocalName) { return $d.InnerText }
    }
    return ''
}

function ConvertFrom-DoorList {
    # Every element whose local name equals ItemElement is a door; id/name/extra by descendant local name.
    param([string]$Text, [string]$ItemElement, [string]$IdField, [string]$NameField, [string[]]$ExtraFields)
    $doc = ConvertTo-XmlDocument $Text
    $doors = New-Object System.Collections.ArrayList
    if (-not $ItemElement) { return @() }
    foreach ($node in $doc.SelectNodes('//*')) {
        if ($node.LocalName -cne $ItemElement) { continue }
        $extra = [ordered]@{}
        foreach ($f in @($ExtraFields)) {
            if ($f) { $extra[$f] = (Get-FirstDescendantText $node $f) }
        }
        [void]$doors.Add([pscustomobject]@{
                id    = (Get-FirstDescendantText $node $IdField)
                name  = (Get-FirstDescendantText $node $NameField)
                extra = $extra
            })
    }
    return @($doors.ToArray())
}

function Get-SoapFault {
    # Returns the fault text (1.1 faultstring, 1.2 Reason/Text) or $null when the response holds no Fault.
    param([string]$Text)
    if (-not $Text) { return $null }
    try { $doc = ConvertTo-XmlDocument $Text } catch { return $null }
    foreach ($node in $doc.SelectNodes('//*')) {
        if ($node.LocalName -ne 'Fault') { continue }
        foreach ($c in $node.ChildNodes) {
            if ($c.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if ($c.LocalName -eq 'faultstring') { return $c.InnerText.Trim() }
            if ($c.LocalName -eq 'Reason') {
                foreach ($t in $c.ChildNodes) {
                    if ($t.NodeType -eq [System.Xml.XmlNodeType]::Element -and $t.LocalName -eq 'Text') { return $t.InnerText.Trim() }
                }
                return $c.InnerText.Trim()
            }
        }
        return 'SOAP Fault (no fault text in the response)'
    }
    return $null
}

function Get-AuditHash {
    # SHA256(prevHash|ts|windowsUser|aeosUser|action|doorId|doorName|httpStatus|ok), hex, UTF-8.
    param([string]$PrevHash, [string]$Ts, [string]$WindowsUser, [string]$AeosUser, [string]$Action,
        [string]$DoorId, [string]$DoorName, [int]$HttpStatus, [bool]$Ok)
    $okText = 'false'
    if ($Ok) { $okText = 'true' }
    $s = @($PrevHash, $Ts, $WindowsUser, $AeosUser, $Action, $DoorId, $DoorName, [string]$HttpStatus, $okText) -join '|'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($s)) }
    finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-AuditChain {
    param($Records)
    $prev = ('0' * 64)
    $i = 0
    foreach ($r in @($Records)) {
        if ($null -eq $r -or $r.PSObject.Properties['parseError']) {
            return [pscustomobject]@{ ChainOk = $false; BadIndex = $i; Count = @($Records).Count }
        }
        $h = Get-AuditHash -PrevHash $prev -Ts ([string]$r.ts) -WindowsUser ([string]$r.windowsUser) -AeosUser ([string]$r.aeosUser) `
            -Action ([string]$r.action) -DoorId ([string]$r.doorId) -DoorName ([string]$r.doorName) `
            -HttpStatus ([int]$r.httpStatus) -Ok ([bool]$r.ok)
        if ([string]$r.prevHash -ne $prev -or [string]$r.hash -ne $h) {
            return [pscustomobject]@{ ChainOk = $false; BadIndex = $i; Count = @($Records).Count }
        }
        $prev = $h
        $i++
    }
    return [pscustomobject]@{ ChainOk = $true; BadIndex = -1; Count = @($Records).Count }
}

function Format-HeaderForLog {
    param([string]$Name, [string]$Value)
    if ($Name -ieq 'Authorization') {
        if ($Value -match '^\s*Basic\b') { return ($Name + ': Basic ****') }
        return ($Name + ': ****')
    }
    return ($Name + ': ' + $Value)
}

function Hide-Secrets {
    # Redaction for the debug log: Authorization header, wsse Password element, then every secret string.
    param([string]$Text, [string[]]$Secrets)
    if ($null -eq $Text) { return '' }
    $t = [regex]::Replace($Text, '(?i)(Authorization\s*:\s*)(Basic|Bearer)\s+\S+', '${1}${2} ****')
    $t = [regex]::Replace($t, '(?is)(<(?:[\w\-]+:)?Password\b[^>]*>)[^<]*(</(?:[\w\-]+:)?Password\s*>)', '${1}****${2}')
    foreach ($s in @($Secrets)) {
        if ($s) { $t = $t.Replace($s, '****') }
    }
    return $t
}

function Format-ExceptionDetail {
    param($Exception)
    $sb = New-Object System.Text.StringBuilder
    $e = $Exception
    $level = 0
    while ($null -ne $e) {
        $label = 'Exception'
        if ($level -gt 0) { $label = 'InnerException[' + $level + ']' }
        [void]$sb.AppendLine($label + ': ' + $e.GetType().FullName)
        [void]$sb.AppendLine('  Message: ' + $e.Message)
        [void]$sb.AppendLine('  HResult: 0x' + ($e.HResult.ToString('X8')))
        if ($e -is [System.Net.WebException]) {
            [void]$sb.AppendLine('  WebException.Status: ' + $e.Status)
            if ($null -ne $e.Response -and $e.Response -is [System.Net.HttpWebResponse]) {
                [void]$sb.AppendLine('  HTTP status: ' + [int]$e.Response.StatusCode + ' ' + $e.Response.StatusDescription)
            }
        }
        if ($e.StackTrace) { [void]$sb.AppendLine('  StackTrace: ' + $e.StackTrace) }
        $e = $e.InnerException
        $level++
    }
    return $sb.ToString().TrimEnd()
}

function Resolve-DataPath {
    param([string]$Value, [string]$BaseDir, [string]$DefaultName)
    if (-not $Value) { return (Join-Path $BaseDir $DefaultName) }
    if ([System.IO.Path]::IsPathRooted($Value)) { return $Value }
    return (Join-Path $BaseDir $Value)
}

function Get-LogTail {
    param([string]$Path, [int]$Lines = 200)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $max = 524288
        $start = [Math]::Max(0, $fs.Length - $max)
        [void]$fs.Seek($start, [System.IO.SeekOrigin]::Begin)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
        $text = $sr.ReadToEnd()
    }
    finally { $fs.Close() }
    $all = @($text -split "\r?\n")
    if ($start -gt 0 -and $all.Count -gt 0) { $all = @($all | Select-Object -Skip 1) }
    while ($all.Count -gt 0 -and $all[$all.Count - 1] -eq '') { $all = @($all | Select-Object -First ($all.Count - 1)) }
    if ($all.Count -gt $Lines) { $all = @($all | Select-Object -Last $Lines) }
    return $all
}

function Get-DefaultConfigJson {
    return @'
{
  "aeosUrl": "",
  "wsdlUrl": "",
  "soapVersion": "1.1",
  "auth": "basic",
  "tlsSkipValidation": false,
  "timeoutSec": 30,
  "namespacePrefix": "aeos",
  "targetNamespace": "",
  "auditFile": "",
  "debugLogFile": "",
  "debugLevel": "full",
  "actions": {
    "listDoors": { "operation": "", "soapAction": "", "body": "", "itemElement": "", "idField": "", "nameField": "", "extraFields": [] },
    "lock":   { "label": "Lock",           "operation": "", "soapAction": "", "body": "", "confirm": true },
    "unlock": { "label": "Unlock",         "operation": "", "soapAction": "", "body": "", "confirm": true },
    "access": { "label": "Provide access", "operation": "", "soapAction": "", "body": "", "confirm": true }
  }
}
'@
}

function Merge-Config {
    # Default keys only; loaded values win; arrays stay arrays; unknown keys are dropped.
    param($Default, $Loaded)
    $out = [ordered]@{}
    foreach ($p in $Default.PSObject.Properties) {
        $name = $p.Name
        $dv = $p.Value
        $has = $false
        $lv = $null
        if ($null -ne $Loaded -and $Loaded -is [System.Management.Automation.PSCustomObject]) {
            $lp = $Loaded.PSObject.Properties[$name]
            if ($lp) { $has = $true; $lv = $lp.Value }
        }
        if ($dv -is [System.Management.Automation.PSCustomObject]) {
            $sub = $null
            if ($has) { $sub = $lv }
            $out[$name] = Merge-Config $dv $sub
        }
        elseif ($dv -is [array]) {
            if ($has -and $null -ne $lv) { $out[$name] = @($lv) } else { $out[$name] = @($dv) }
        }
        elseif ($has -and $null -ne $lv) { $out[$name] = $lv }
        else { $out[$name] = $dv }
    }
    return [pscustomobject]$out
}

function Test-ConfigObject {
    # Returns a list of problems (empty = valid).
    param($Config)
    $errs = New-Object System.Collections.Generic.List[string]
    $ncname = '^[A-Za-z_][A-Za-z0-9_.\-]*$'
    if (@('1.1', '1.2') -notcontains [string]$Config.soapVersion) { $errs.Add('soapVersion must be 1.1 or 1.2.') }
    if (@('basic', 'wsse') -notcontains [string]$Config.auth) { $errs.Add('auth must be basic or wsse.') }
    if (@('full', 'basic') -notcontains [string]$Config.debugLevel) { $errs.Add('debugLevel must be full or basic.') }
    if ($Config.tlsSkipValidation -isnot [bool]) { $errs.Add('tlsSkipValidation must be true or false.') }
    $t = 0
    if (-not [int]::TryParse([string]$Config.timeoutSec, [ref]$t) -or $t -lt 1 -or $t -gt 600) { $errs.Add('timeoutSec must be a number from 1 to 600.') }
    foreach ($k in @('aeosUrl', 'wsdlUrl')) {
        $v = [string]$Config.$k
        if ($v -and $v -notmatch '^https?://\S+$') { $errs.Add($k + ' must start with http:// or https://.') }
    }
    $ns = [string]$Config.namespacePrefix
    if ($ns -notmatch $ncname -or @('soapenv', 'wsse', 'xml', 'xmlns') -contains $ns.ToLowerInvariant()) {
        $errs.Add('namespacePrefix must be a plain XML name (letters, digits, - _ .) and not soapenv / wsse / xml / xmlns.')
    }
    foreach ($a in @('listDoors', 'lock', 'unlock', 'access')) {
        $act = $Config.actions.$a
        if ($null -eq $act) { $errs.Add('actions.' + $a + ' is missing.'); continue }
        $body = [string]$act.body
        if ($body) {
            $env = New-SoapEnvelope -Body (Expand-Template -Body $body -Id '1' -Name 'sample' -Ns $ns -Tns ([string]$Config.targetNamespace)) `
                -SoapVersion ([string]$Config.soapVersion) -Auth 'basic' -Ns $ns -Tns ([string]$Config.targetNamespace)
            $perr = Get-XmlParseError $env
            if ($perr) { $errs.Add('actions.' + $a + '.body is not well-formed XML after substitution: ' + $perr) }
        }
    }
    $ld = $Config.actions.listDoors
    if ($ld) {
        foreach ($k in @('itemElement', 'idField', 'nameField')) {
            $v = [string]$ld.$k
            if ($v -and $v -notmatch $ncname) { $errs.Add('actions.listDoors.' + $k + ' must be a plain XML element name.') }
        }
        foreach ($f in @($ld.extraFields)) {
            if ($f -and ([string]$f) -notmatch $ncname) { $errs.Add('actions.listDoors.extraFields entries must be plain XML element names.') }
        }
    }
    return $errs.ToArray()
}

function New-ErrorResult {
    param([int]$Status, [string]$Code, [string]$Message)
    return @{ Status = $Status; Json = @{ error = @{ code = $Code; message = $Message } } }
}

function New-ApiException {
    param([int]$Status, [string]$Code, [string]$Message)
    $ex = New-Object System.Exception($Message)
    $ex.Data['code'] = $Code
    $ex.Data['status'] = $Status
    return $ex
}

function New-RequestId {
    return [guid]::NewGuid().ToString('N').Substring(0, 8)
}

# ============================================================================
# Script state: logging, config, audit
# ============================================================================

function Get-RedactionSecrets {
    $list = New-Object System.Collections.Generic.List[string]
    if ($null -ne $script:Cred) {
        try {
            $nc = $script:Cred.GetNetworkCredential()
            if ($nc.Password) {
                $list.Add($nc.Password)
                $list.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($nc.UserName + ':' + $nc.Password)))
            }
        }
        catch { }
    }
    return $list.ToArray()
}

function Write-DebugLog {
    param([string]$Rid, [string]$Message, [string]$Level = 'INFO')
    if (-not $script:DebugLogPath) { return }
    try {
        $text = Hide-Secrets -Text $Message -Secrets @(Get-RedactionSecrets)
        $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $prefix = $ts + ' [' + $Rid + '] ' + $Level + ' '
        $lines = @($text -split "\r?\n")
        $out = (($lines | ForEach-Object { $prefix + $_ }) -join "`r`n") + "`r`n"
        $dir = Split-Path -Parent $script:DebugLogPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $fi = New-Object System.IO.FileInfo($script:DebugLogPath)
        if ($fi.Exists -and $fi.Length -gt 10485760) {
            $old = $script:DebugLogPath + '.1'
            if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force }
            [System.IO.File]::Move($script:DebugLogPath, $old)
        }
        [System.IO.File]::AppendAllText($script:DebugLogPath, $out, (New-Object System.Text.UTF8Encoding($false)))
    }
    catch { }
}

function Get-EnvironmentText {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('Aeos-DoorConsole version: ' + $script:Version)
    [void]$sb.AppendLine('Time (UTC): ' + [DateTime]::UtcNow.ToString('o'))
    [void]$sb.AppendLine('PowerShell: ' + $PSVersionTable.PSVersion + ' (' + $PSVersionTable.PSEdition + ')')
    [void]$sb.AppendLine('CLR: ' + [Environment]::Version)
    try {
        $rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop).Release
        [void]$sb.AppendLine('.NET Framework release key: ' + $rel)
    }
    catch { [void]$sb.AppendLine('.NET Framework release key: unknown') }
    [void]$sb.AppendLine('OS: ' + [Environment]::OSVersion.VersionString)
    [void]$sb.AppendLine('Process bitness: ' + $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }))
    [void]$sb.AppendLine('Machine: ' + [Environment]::MachineName)
    [void]$sb.AppendLine('User: ' + [Environment]::UserDomainName + '\' + [Environment]::UserName)
    [void]$sb.AppendLine('Culture: ' + [System.Globalization.CultureInfo]::CurrentCulture.Name)
    [void]$sb.AppendLine('Enabled TLS protocols: ' + [System.Net.ServicePointManager]::SecurityProtocol)
    [void]$sb.AppendLine('Script directory: ' + $script:ScriptDir)
    [void]$sb.AppendLine('Config file: ' + $script:ConfigPath)
    [void]$sb.AppendLine('Debug log: ' + $script:DebugLogPath)
    [void]$sb.AppendLine('Audit file: ' + $script:AuditPath)
    return $sb.ToString()
}

function Write-StartupBlock {
    param([string]$Url)
    $rid = 'startup'
    Write-DebugLog $rid '==================== Aeos-DoorConsole start ===================='
    Write-DebugLog $rid ((Get-EnvironmentText).TrimEnd())
    Write-DebugLog $rid ('Listener URL: ' + $Url)
    Write-DebugLog $rid ('Config (no secrets are stored in the config):' + "`r`n" + (ConvertTo-Json -InputObject $script:Config -Depth 10))
}

function Initialize-Paths {
    $script:AuditPath = Resolve-DataPath -Value ([string]$script:Config.auditFile) -BaseDir $script:ScriptDir -DefaultName 'aeos-console-audit.jsonl'
    $script:DebugLogPath = Resolve-DataPath -Value ([string]$script:Config.debugLogFile) -BaseDir $script:ScriptDir -DefaultName 'aeos-console-debug.log'
    $script:LastAuditHash = $script:ZeroHash
    $recs = @(Read-AuditRecords)
    if ($recs.Count -gt 0) {
        $last = $recs[$recs.Count - 1]
        if (-not $last.PSObject.Properties['parseError'] -and $last.hash) { $script:LastAuditHash = [string]$last.hash }
    }
}

function Read-AuditRecords {
    if (-not (Test-Path -LiteralPath $script:AuditPath)) { return @() }
    $fs = [System.IO.File]::Open($script:AuditPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try { $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8); $text = $sr.ReadToEnd() }
    finally { $fs.Close() }
    $recs = New-Object System.Collections.ArrayList
    foreach ($line in ($text -split "\r?\n")) {
        if (-not $line.Trim()) { continue }
        try { [void]$recs.Add((ConvertFrom-Json -InputObject $line)) }
        catch { [void]$recs.Add([pscustomobject]@{ parseError = $true }) }
    }
    return @($recs.ToArray())
}

function Write-AuditRecord {
    param([string]$Action, [string]$DoorId, [string]$DoorName, [int]$HttpStatus, [bool]$Ok, [string]$Fault)
    $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $win = [Environment]::UserDomainName + '\' + [Environment]::UserName
    $aeos = ''
    if ($null -ne $script:Cred) { $aeos = $script:Cred.UserName }
    $prev = $script:LastAuditHash
    $hash = Get-AuditHash -PrevHash $prev -Ts $ts -WindowsUser $win -AeosUser $aeos -Action $Action -DoorId $DoorId -DoorName $DoorName -HttpStatus $HttpStatus -Ok $Ok
    $rec = [ordered]@{
        ts = $ts; windowsUser = $win; aeosUser = $aeos; action = $Action; doorId = $DoorId; doorName = $DoorName
        httpStatus = $HttpStatus; ok = $Ok; fault = $Fault; prevHash = $prev; hash = $hash
    }
    $line = ConvertTo-Json -InputObject $rec -Compress
    $dir = Split-Path -Parent $script:AuditPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    [System.IO.File]::AppendAllText($script:AuditPath, $line + "`n", (New-Object System.Text.UTF8Encoding($false)))
    $script:LastAuditHash = $hash
}

function Save-ConfigFile {
    param($Config, [string]$Path)
    $text = ConvertTo-Json -InputObject $Config -Depth 10
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $tmp = $Path + '.tmp'
    [System.IO.File]::WriteAllText($tmp, $text, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) }
    else { [System.IO.File]::Move($tmp, $Path) }
}

function Import-ConfigFile {
    param([string]$Path)
    $default = ConvertFrom-Json -InputObject (Get-DefaultConfigJson)
    if (-not (Test-Path -LiteralPath $Path)) {
        Save-ConfigFile -Config $default -Path $Path
        return $default
    }
    $loaded = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($Path))
    return (Merge-Config $default $loaded)
}

# ============================================================================
# AEOS HTTP / SOAP
# ============================================================================

function Initialize-TlsCallbackType {
    if ('AeosTlsCallback' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class AeosTlsCallback
{
    public bool Skip;
    public List<string> Lines = new List<string>();

    public RemoteCertificateValidationCallback Callback
    {
        get { return new RemoteCertificateValidationCallback(Validate); }
    }

    private bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        try
        {
            Lines.Add("TLS server certificate callback: SslPolicyErrors=" + errors + " skipValidation=" + Skip);
            if (cert != null)
            {
                X509Certificate2 c2 = new X509Certificate2(cert);
                Lines.Add("  Subject:    " + c2.Subject);
                Lines.Add("  Issuer:     " + c2.Issuer);
                Lines.Add("  Thumbprint: " + c2.Thumbprint);
                Lines.Add("  NotBefore:  " + c2.NotBefore.ToString("o"));
                Lines.Add("  NotAfter:   " + c2.NotAfter.ToString("o"));
                foreach (X509Extension ext in c2.Extensions)
                {
                    if (ext.Oid != null && ext.Oid.Value == "2.5.29.17")
                    {
                        Lines.Add("  SANs:       " + ext.Format(false));
                    }
                }
            }
            else
            {
                Lines.Add("  (no certificate presented)");
            }
            if (chain != null && chain.ChainStatus != null)
            {
                foreach (X509ChainStatus st in chain.ChainStatus)
                {
                    Lines.Add("  Chain status: " + st.Status + " " + (st.StatusInformation == null ? "" : st.StatusInformation.Trim()));
                }
            }
            Lines.Add("  Decision: " + (Skip ? "accepted (validation skipped by config)" : (errors == SslPolicyErrors.None ? "accepted" : "REJECTED")));
        }
        catch (Exception ex)
        {
            Lines.Add("TLS callback logging failed: " + ex.Message);
        }
        if (Skip) { return true; }
        return errors == SslPolicyErrors.None;
    }
}
'@
}

function Invoke-AeosHttp {
    param([string]$Rid, [string]$What, [string]$Method, [string]$Url, [string]$ContentType,
        [string]$SoapActionHeader, [string]$Body, [bool]$Basic)
    $cfg = $script:Config
    $full = ([string]$cfg.debugLevel -ne 'basic')
    Initialize-TlsCallbackType
    $cb = New-Object AeosTlsCallback
    $cb.Skip = ($cfg.tlsSkipValidation -eq $true)
    $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
    $req.Method = $Method
    $req.Timeout = ([int]$cfg.timeoutSec) * 1000
    $req.ReadWriteTimeout = ([int]$cfg.timeoutSec) * 1000
    $req.Proxy = $null
    $req.KeepAlive = $false
    $req.AllowAutoRedirect = $false
    $req.UserAgent = 'Aeos-DoorConsole/' + $script:Version
    $req.ServicePoint.Expect100Continue = $false
    if ($Url -match '^https') { $req.ServerCertificateValidationCallback = $cb.Callback }
    $hdr = New-Object System.Collections.Generic.List[string]
    $hdr.Add('Host: ' + $req.Host)
    $hdr.Add('User-Agent: ' + $req.UserAgent)
    if ($Method -eq 'POST') {
        $req.ContentType = $ContentType
        $hdr.Add('Content-Type: ' + $ContentType)
        if ($SoapActionHeader) {
            $req.Headers.Add('SOAPAction', $SoapActionHeader)
            $hdr.Add('SOAPAction: ' + $SoapActionHeader)
        }
    }
    if ($Basic -and $null -ne $script:Cred) {
        $nc = $script:Cred.GetNetworkCredential()
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($nc.UserName + ':' + $nc.Password))
        $req.Headers.Add('Authorization', 'Basic ' + $b64)
        $hdr.Add((Format-HeaderForLog 'Authorization' ('Basic ' + $b64)))
    }
    $bytes = $null
    if ($Method -eq 'POST') {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $req.ContentLength = $bytes.Length
        $hdr.Add('Content-Length: ' + $bytes.Length)
    }
    Write-DebugLog $Rid ('>>> REQUEST [' + $What + '] ' + $Method + ' ' + $Url + ' (timeout ' + $cfg.timeoutSec + ' s, tlsSkipValidation=' + $cb.Skip + ')')
    foreach ($h in $hdr) { Write-DebugLog $Rid ('>>> header ' + $h) }
    if ($Method -eq 'POST') {
        if ($full) {
            Write-DebugLog $Rid ('>>> body (' + $Body.Length + ' chars):' + "`r`n" + $Body + "`r`n" + '>>> end body')
        }
        else { Write-DebugLog $Rid ('>>> body (' + $Body.Length + ' chars, not logged at debugLevel basic)') }
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = $null
    $webEx = $null
    try {
        if ($null -ne $bytes) {
            $rs = $req.GetRequestStream()
            try { $rs.Write($bytes, 0, $bytes.Length) } finally { $rs.Close() }
        }
        $resp = $req.GetResponse()
    }
    catch [System.Net.WebException] {
        $webEx = $_.Exception
        $resp = $webEx.Response
    }
    catch {
        $sw.Stop()
        foreach ($l in $cb.Lines) { Write-DebugLog $Rid $l }
        Write-DebugLog $Rid ('!!! REQUEST FAILED [' + $What + '] after ' + $sw.ElapsedMilliseconds + ' ms' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
        throw (New-ApiException 502 'aeos_unreachable' ('Cannot send the request to AEOS: ' + $_.Exception.Message))
    }
    $sw.Stop()
    foreach ($l in $cb.Lines) { Write-DebugLog $Rid $l }
    if ($null -eq $resp) {
        $msgs = New-Object System.Collections.Generic.List[string]
        $e = $webEx
        while ($null -ne $e) { $msgs.Add($e.Message); $e = $e.InnerException }
        Write-DebugLog $Rid ('!!! NO RESPONSE [' + $What + '] after ' + $sw.ElapsedMilliseconds + ' ms' + "`r`n" + (Format-ExceptionDetail $webEx)) 'ERROR'
        throw (New-ApiException 502 'aeos_unreachable' ('Cannot reach AEOS (' + $webEx.Status + '): ' + ($msgs -join ' -> ')))
    }
    $status = [int]$resp.StatusCode
    $respHeaders = New-Object System.Collections.Generic.List[string]
    foreach ($k in $resp.Headers.AllKeys) { $respHeaders.Add($k + ': ' + $resp.Headers[$k]) }
    $text = ''
    try {
        $rsr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $text = $rsr.ReadToEnd()
        $rsr.Close()
    }
    catch {
        Write-DebugLog $Rid ('!!! reading the response body failed' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
    }
    finally { $resp.Close() }
    Write-DebugLog $Rid ('<<< RESPONSE [' + $What + '] HTTP ' + $status + ' in ' + $sw.ElapsedMilliseconds + ' ms')
    foreach ($h in $respHeaders) { Write-DebugLog $Rid ('<<< header ' + $h) }
    if ($full) {
        $shown = $text
        $note = ''
        if ($shown.Length -gt 1048576) { $shown = $shown.Substring(0, 1048576); $note = ', truncated at 1 MB' }
        Write-DebugLog $Rid ('<<< body (' + $text.Length + ' chars' + $note + '):' + "`r`n" + $shown + "`r`n" + '<<< end body')
    }
    else { Write-DebugLog $Rid ('<<< body (' + $text.Length + ' chars, not logged at debugLevel basic)') }
    return [pscustomobject]@{ Status = $status; Body = $text }
}

function Assert-CanCall {
    $cfg = $script:Config
    if (-not $cfg.aeosUrl) { throw (New-ApiException 400 'not_configured' 'The AEOS URL is not set. Open the Setup tab.') }
    if ($null -eq $script:Cred) { throw (New-ApiException 401 'not_logged_in' 'Log in with the AEOS user first.') }
}

function Invoke-SoapCall {
    param([string]$Rid, [string]$What, [string]$SoapAction, [string]$BodyTemplate, [string]$Id = '', [string]$Name = '')
    Assert-CanCall
    $cfg = $script:Config
    $ns = [string]$cfg.namespacePrefix
    $tns = [string]$cfg.targetNamespace
    $body = Expand-Template -Body $BodyTemplate -Id $Id -Name $Name -Ns $ns -Tns $tns
    $pw = ''
    if ($cfg.auth -eq 'wsse') { $pw = $script:Cred.GetNetworkCredential().Password }
    $envelope = New-SoapEnvelope -Body $body -SoapVersion ([string]$cfg.soapVersion) -Auth ([string]$cfg.auth) `
        -User $script:Cred.UserName -Password $pw -Ns $ns -Tns $tns
    $perr = Get-XmlParseError $envelope
    if ($perr) {
        Write-DebugLog $Rid ('Refused before sending: request is not well-formed XML after substitution: ' + $perr) 'ERROR'
        throw (New-ApiException 400 'bad_template' ('The request is not well-formed XML after substitution: ' + $perr))
    }
    $h = Get-SoapRequestHeaders -SoapVersion ([string]$cfg.soapVersion) -SoapAction $SoapAction
    $r = Invoke-AeosHttp -Rid $Rid -What $What -Method 'POST' -Url ([string]$cfg.aeosUrl) -ContentType $h.ContentType `
        -SoapActionHeader $h.SoapActionHeader -Body $envelope -Basic ($cfg.auth -eq 'basic')
    $fault = Get-SoapFault $r.Body
    $ok = ($r.Status -ge 200 -and $r.Status -lt 300 -and $null -eq $fault)
    Write-DebugLog $Rid ('Call result [' + $What + ']: httpStatus=' + $r.Status + ' ok=' + $ok + $(if ($fault) { ' fault="' + $fault + '"' } else { '' }))
    return @{ httpStatus = $r.Status; ok = $ok; fault = $fault; response = (Format-XmlPretty $r.Body); rawText = $r.Body }
}

function Get-WsdlInfoFromServer {
    param([string]$Rid)
    $cfg = $script:Config
    if (-not $cfg.aeosUrl -and -not $cfg.wsdlUrl) { throw (New-ApiException 400 'not_configured' 'Set the AEOS URL (or the WSDL URL) on the Setup tab first.') }
    $url = [string]$cfg.wsdlUrl
    if (-not $url) { $url = [string]$cfg.aeosUrl + '?wsdl' }
    $r = Invoke-AeosHttp -Rid $Rid -What 'wsdl' -Method 'GET' -Url $url -ContentType '' -SoapActionHeader '' -Body '' -Basic ($null -ne $script:Cred)
    if ($r.Status -lt 200 -or $r.Status -ge 300) {
        throw (New-ApiException 502 'wsdl_http' ('The WSDL request returned HTTP ' + $r.Status + '. Check the URL and that you are logged in.'))
    }
    try { return (Read-WsdlInfo $r.Body) }
    catch {
        Write-DebugLog $Rid ('WSDL parse failed' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
        throw (New-ApiException 502 'wsdl_parse' ('The WSDL could not be parsed: ' + $_.Exception.Message))
    }
}

function Invoke-DoorAction {
    param([string]$Rid, [string]$Action, [string]$Id, [string]$Name)
    if (@('lock', 'unlock', 'access') -notcontains $Action) { throw (New-ApiException 400 'bad_action' 'Unknown action.') }
    $a = $script:Config.actions.$Action
    if (-not $a.operation) { throw (New-ApiException 400 'not_configured' ('The ' + $Action + ' action is not mapped on the Setup tab.')) }
    Assert-CanCall
    $result = $null
    $caught = $null
    try { $result = Invoke-SoapCall -Rid $Rid -What $Action -SoapAction ([string]$a.soapAction) -BodyTemplate ([string]$a.body) -Id $Id -Name $Name }
    catch { $caught = $_.Exception }
    $status = 0
    $ok = $false
    $fault = $null
    if ($null -ne $result) { $status = $result.httpStatus; $ok = $result.ok; $fault = $result.fault }
    elseif ($null -ne $caught) { $fault = $caught.Message }
    Write-AuditRecord -Action $Action -DoorId $Id -DoorName $Name -HttpStatus $status -Ok $ok -Fault $fault
    Write-DebugLog $Rid ('Audit record written: action=' + $Action + ' doorId=' + $Id + ' ok=' + $ok)
    if ($null -ne $caught) { throw $caught }
    return @{ ok = $result.ok; httpStatus = $result.httpStatus; fault = $result.fault; response = $result.response }
}

function Get-DoorsFromServer {
    param([string]$Rid)
    $a = $script:Config.actions.listDoors
    if (-not $a.operation) { throw (New-ApiException 400 'not_configured' 'The list doors action is not mapped on the Setup tab.') }
    if (-not $a.itemElement -or -not $a.idField) { throw (New-ApiException 400 'not_configured' 'Set the door element and the id field on the Setup tab.') }
    $r = Invoke-SoapCall -Rid $Rid -What 'listDoors' -SoapAction ([string]$a.soapAction) -BodyTemplate ([string]$a.body)
    $doors = @()
    if ($r.ok) {
        try { $doors = @(ConvertFrom-DoorList -Text $r.rawText -ItemElement ([string]$a.itemElement) -IdField ([string]$a.idField) -NameField ([string]$a.nameField) -ExtraFields @($a.extraFields)) }
        catch {
            Write-DebugLog $Rid ('Door list parse failed' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
            throw (New-ApiException 502 'parse_failed' ('The response could not be parsed: ' + $_.Exception.Message))
        }
        Write-DebugLog $Rid ('Door list parsed: ' + $doors.Count + ' door(s) with element "' + $a.itemElement + '"')
    }
    return @{ ok = $r.ok; httpStatus = $r.httpStatus; fault = $r.fault; doors = @($doors); raw = $r.response }
}

# ============================================================================
# Diagnostics zip
# ============================================================================

function Add-ZipFile {
    param($Zip, [string]$Source, [string]$EntryName)
    if (-not (Test-Path -LiteralPath $Source)) { return }
    $entry = $Zip.CreateEntry($EntryName)
    $es = $entry.Open()
    $fs = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try { $fs.CopyTo($es) } finally { $fs.Close(); $es.Close() }
}

function Add-ZipText {
    param($Zip, [string]$Text, [string]$EntryName)
    $entry = $Zip.CreateEntry($EntryName)
    $es = $entry.Open()
    try {
        $b = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
        $es.Write($b, 0, $b.Length)
    }
    finally { $es.Close() }
}

function New-DiagnosticsZip {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $dir = Split-Path -Parent $script:DebugLogPath
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $name = 'aeos-console-diag-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip'
    $path = Join-Path $dir $name
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            Add-ZipFile $zip $script:DebugLogPath ([System.IO.Path]::GetFileName($script:DebugLogPath))
            Add-ZipFile $zip ($script:DebugLogPath + '.1') ([System.IO.Path]::GetFileName($script:DebugLogPath) + '.1')
            Add-ZipText $zip (ConvertTo-Json -InputObject $script:Config -Depth 10) 'config.json'
            Add-ZipFile $zip $script:AuditPath ([System.IO.Path]::GetFileName($script:AuditPath))
            Add-ZipText $zip (Get-EnvironmentText) 'environment.txt'
        }
        finally { $zip.Dispose() }
    }
    finally { $fs.Close() }
    return $path
}

# ============================================================================
# HTTP server
# ============================================================================

function Read-RequestJson {
    param($Request)
    $sr = New-Object System.IO.StreamReader($Request.InputStream, [System.Text.Encoding]::UTF8)
    $text = $sr.ReadToEnd()
    if ($text.Length -gt 2097152) { throw (New-ApiException 413 'too_large' 'Request body too large.') }
    if (-not $text.Trim()) { return $null }
    try { return (ConvertFrom-Json -InputObject $text) }
    catch { throw (New-ApiException 400 'bad_json' 'The request body is not valid JSON.') }
}

function Invoke-Route {
    param($Ctx, [string]$Rid)
    $req = $Ctx.Request
    $method = $req.HttpMethod.ToUpperInvariant()
    $path = $req.Url.AbsolutePath
    if (-not $req.IsLocal) { return (New-ErrorResult 403 'forbidden' 'Requests are accepted from this computer only.') }
    if ($method -eq 'GET' -and $path -eq '/') {
        $html = $script:PageHtml.Replace('__TOKEN__', $script:Token)
        return @{ Status = 200; Bytes = [System.Text.Encoding]::UTF8.GetBytes($html); ContentType = 'text/html; charset=utf-8'
            Headers = @{ 'Content-Security-Policy' = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'" } }
    }
    if ($method -eq 'GET' -and $path -eq '/health') {
        return @{ Status = 200; Json = @{ status = 'ok'; version = $script:Version } }
    }
    if (-not $path.StartsWith('/api/v1/')) { return (New-ErrorResult 404 'not_found' 'Not found.') }
    $tok = $req.Headers['X-Console-Token']
    if (-not $tok -or $tok -cne $script:Token) { return (New-ErrorResult 403 'forbidden' 'Missing or wrong X-Console-Token.') }
    $origin = $req.Headers['Origin']
    if ($origin -and $origin -cne ('http://localhost:' + $script:Port)) { return (New-ErrorResult 403 'forbidden' 'Origin not allowed.') }

    switch ($method + ' ' + $path) {
        'GET /api/v1/config' {
            return @{ Status = 200; Json = (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $script:Config -Depth 10)) }
        }
        'PUT /api/v1/config' {
            $in = Read-RequestJson $req
            if ($null -eq $in) { throw (New-ApiException 400 'bad_json' 'Empty request body.') }
            $merged = Merge-Config (ConvertFrom-Json -InputObject (Get-DefaultConfigJson)) $in
            $problems = @(Test-ConfigObject $merged)
            if ($problems.Count -gt 0) { throw (New-ApiException 400 'invalid_config' ($problems -join ' ')) }
            Save-ConfigFile -Config $merged -Path $script:ConfigPath
            $script:Config = $merged
            Initialize-Paths
            Write-DebugLog $Rid ('Config saved to ' + $script:ConfigPath + "`r`n" + (ConvertTo-Json -InputObject $script:Config -Depth 10))
            return @{ Status = 200; Json = @{ ok = $true } }
        }
        'POST /api/v1/login' {
            $in = Read-RequestJson $req
            $u = ''
            $p = ''
            if ($null -ne $in) { $u = [string]$in.user; $p = [string]$in.password }
            if (-not $u -or -not $p) { throw (New-ApiException 400 'bad_login' 'User and password are required.') }
            $ss = New-Object System.Security.SecureString
            foreach ($ch in $p.ToCharArray()) { $ss.AppendChar($ch) }
            $ss.MakeReadOnly()
            $script:Cred = New-Object System.Management.Automation.PSCredential($u, $ss)
            Write-DebugLog $Rid ('Login: user=' + $u)
            return @{ Status = 200; Json = @{ loggedIn = $true; user = $u } }
        }
        'POST /api/v1/logout' {
            Write-DebugLog $Rid 'Logout'
            $script:Cred = $null
            return @{ Status = 200; Json = @{ loggedIn = $false; user = '' } }
        }
        'GET /api/v1/session' {
            $u = ''
            if ($null -ne $script:Cred) { $u = $script:Cred.UserName }
            return @{ Status = 200; Json = @{ loggedIn = ($null -ne $script:Cred); user = $u } }
        }
        'GET /api/v1/wsdl' {
            $info = Get-WsdlInfoFromServer -Rid $Rid
            return @{ Status = 200; Json = @{ targetNamespace = $info.targetNamespace; soapVersion = $info.soapVersion; operations = @($info.operations) } }
        }
        'POST /api/v1/call' {
            $in = Read-RequestJson $req
            if ($null -eq $in -or -not [string]$in.body) { throw (New-ApiException 400 'bad_request' 'A request body (XML) is required.') }
            $r = Invoke-SoapCall -Rid $Rid -What ('raw ' + [string]$in.operation) -SoapAction ([string]$in.soapAction) -BodyTemplate ([string]$in.body)
            return @{ Status = 200; Json = @{ httpStatus = $r.httpStatus; ok = $r.ok; fault = $r.fault; response = $r.response } }
        }
        'GET /api/v1/doors' {
            return @{ Status = 200; Json = (Get-DoorsFromServer -Rid $Rid) }
        }
        'POST /api/v1/doors/action' {
            $in = Read-RequestJson $req
            if ($null -eq $in) { throw (New-ApiException 400 'bad_request' 'Empty request body.') }
            return @{ Status = 200; Json = (Invoke-DoorAction -Rid $Rid -Action ([string]$in.action) -Id ([string]$in.id) -Name ([string]$in.name)) }
        }
        'GET /api/v1/audit' {
            $limit = 50
            $q = $req.QueryString['limit']
            $tmp = 0
            if ($q -and [int]::TryParse($q, [ref]$tmp) -and $tmp -gt 0 -and $tmp -le 1000) { $limit = $tmp }
            $recs = @(Read-AuditRecords)
            $chain = Test-AuditChain $recs
            $last = @($recs | Select-Object -Last $limit)
            return @{ Status = 200; Json = @{ records = $last; chainOk = $chain.ChainOk; badIndex = $chain.BadIndex; total = $recs.Count } }
        }
        'GET /api/v1/debuglog' {
            $n = 200
            $q = $req.QueryString['lines']
            $tmp = 0
            if ($q -and [int]::TryParse($q, [ref]$tmp) -and $tmp -gt 0 -and $tmp -le 5000) { $n = $tmp }
            return @{ Status = 200; Json = @{ file = $script:DebugLogPath; lines = @(Get-LogTail -Path $script:DebugLogPath -Lines $n) } }
        }
        'GET /api/v1/debuglog/download' {
            if (-not (Test-Path -LiteralPath $script:DebugLogPath)) { throw (New-ApiException 404 'not_found' 'No debug log yet.') }
            $fs = [System.IO.File]::Open($script:DebugLogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try { $ms = New-Object System.IO.MemoryStream; $fs.CopyTo($ms); $bytes = $ms.ToArray() } finally { $fs.Close() }
            return @{ Status = 200; Bytes = $bytes; ContentType = 'text/plain; charset=utf-8'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="' + [System.IO.Path]::GetFileName($script:DebugLogPath) + '"' } }
        }
        'POST /api/v1/diagnostics' {
            $p = New-DiagnosticsZip
            Write-DebugLog $Rid ('Diagnostics zip created: ' + $p)
            return @{ Status = 200; Json = @{ path = $p; fileName = [System.IO.Path]::GetFileName($p) } }
        }
        'GET /api/v1/diagnostics/download' {
            $f = [string]$req.QueryString['file']
            if ($f -notmatch '^aeos-console-diag-\d{8}-\d{6}\.zip$') { throw (New-ApiException 400 'bad_request' 'Bad file name.') }
            $p = Join-Path (Split-Path -Parent $script:DebugLogPath) $f
            if (-not (Test-Path -LiteralPath $p)) { throw (New-ApiException 404 'not_found' 'No such diagnostics file.') }
            return @{ Status = 200; Bytes = [System.IO.File]::ReadAllBytes($p); ContentType = 'application/zip'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="' + $f + '"' } }
        }
        default { return (New-ErrorResult 404 'not_found' 'Unknown API path or method.') }
    }
}

function Send-Result {
    param($Ctx, $Result, [string]$Rid)
    $resp = $Ctx.Response
    $resp.StatusCode = [int]$Result.Status
    $resp.Headers.Add('X-Request-Id', $Rid)
    $resp.Headers.Add('Cache-Control', 'no-store')
    $resp.Headers.Add('X-Content-Type-Options', 'nosniff')
    $resp.Headers.Add('X-Frame-Options', 'DENY')
    if ($Result.ContainsKey('Headers')) {
        foreach ($k in $Result.Headers.Keys) { $resp.Headers.Add($k, [string]$Result.Headers[$k]) }
    }
    if ($Result.ContainsKey('Json')) {
        $j = $Result.Json
        if ($j -is [System.Collections.IDictionary]) { $j['requestId'] = $Rid }
        else { Add-Member -InputObject $j -NotePropertyName requestId -NotePropertyValue $Rid -Force }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $j -Depth 10 -Compress))
        $resp.ContentType = 'application/json; charset=utf-8'
    }
    else {
        $bytes = $Result.Bytes
        $resp.ContentType = $Result.ContentType
    }
    $resp.ContentLength64 = $bytes.Length
    $resp.OutputStream.Write($bytes, 0, $bytes.Length)
    $resp.OutputStream.Close()
}

function Invoke-Request {
    param($Ctx)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rid = New-RequestId
    $method = $Ctx.Request.HttpMethod
    $path = $Ctx.Request.Url.AbsolutePath
    $quiet = ($method -eq 'GET' -and $path -eq '/api/v1/debuglog')
    $result = $null
    $errNote = ''
    try { $result = Invoke-Route -Ctx $Ctx -Rid $rid }
    catch {
        $e = $_.Exception
        if ($e.Data -and $e.Data.Contains('code')) {
            $result = New-ErrorResult ([int]$e.Data['status']) ([string]$e.Data['code']) $e.Message
            $errNote = ' error=' + $e.Data['code'] + ': ' + $e.Message
        }
        else {
            Write-DebugLog $rid ('Unhandled exception in ' + $method + ' ' + $path + "`r`n" + (Format-ExceptionDetail $e)) 'ERROR'
            $result = New-ErrorResult 500 'internal' ('Unexpected error: ' + $e.Message)
            $errNote = ' unhandled exception (see above)'
        }
    }
    try { Send-Result -Ctx $Ctx -Result $result -Rid $rid }
    catch { Write-DebugLog $rid ('Sending the response failed: ' + $_.Exception.Message) 'ERROR' }
    $sw.Stop()
    if (-not $quiet -or $result.Status -ge 400) {
        Write-DebugLog $rid ('API ' + $method + ' ' + $path + ' -> ' + $result.Status + ' (' + $sw.ElapsedMilliseconds + ' ms)' + $errNote)
    }
}

# ============================================================================
# Embedded page
# ============================================================================

$script:PageHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="console-token" content="__TOKEN__">
<title>AEOS Door Console</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:14px/1.4 Segoe UI,Arial,sans-serif;color:#1d2733;background:#f3f5f8}
header{background:#14304f;color:#fff;padding:10px 16px;display:flex;flex-wrap:wrap;gap:12px;align-items:center}
header h1{font-size:18px;margin:0 12px 0 0}
header input{padding:5px 7px;border:1px solid #8aa;border-radius:3px;width:140px}
header button{padding:5px 12px}
#aeos-url{opacity:.85;font-size:12px}
#banners div{padding:8px 16px;font-weight:600}
.warn{background:#ffe9b0;color:#6a4500}
.err{background:#ffd2d2;color:#7a0000}
nav{display:flex;gap:4px;padding:10px 16px 0}
nav button{padding:8px 16px;border:1px solid #c5cdd8;border-bottom:none;background:#e4e9f0;border-radius:4px 4px 0 0;cursor:pointer}
nav button.active{background:#fff;font-weight:600}
.panel{display:none;background:#fff;margin:0 16px 16px;padding:16px;border:1px solid #c5cdd8;min-height:300px}
.panel.active{display:block}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #e1e6ed;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f3f5f8}
button{font:inherit;cursor:pointer;padding:5px 12px}
button.act{margin-right:6px}
button:disabled{opacity:.5;cursor:default}
.result.ok{color:#0a6b2a;font-weight:600}
.result.bad{color:#a00000;font-weight:600}
fieldset{margin:0 0 14px;border:1px solid #c5cdd8}
legend{font-weight:600}
label{display:inline-block;margin:3px 12px 3px 0}
label span{display:block;font-size:12px;color:#52606f}
input[type=text],input[type=number],select,textarea{padding:5px 7px;border:1px solid #aab;border-radius:3px;font:inherit}
textarea{width:100%;min-height:80px;font:12px Consolas,monospace}
pre{background:#101820;color:#d8e4f0;padding:10px;overflow:auto;max-height:480px;font:12px Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.msg{margin:8px 0;min-height:20px}
.msg.bad{color:#a00000;font-weight:600}
.msg.good{color:#0a6b2a;font-weight:600}
.setup-bar{position:sticky;bottom:0;background:#fff;border-top:1px solid #c5cdd8;padding:2px 0;z-index:5}
.setup-bar p{margin:6px 0}
#confirm{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);align-items:center;justify-content:center;z-index:10}
#confirm .box{background:#fff;padding:20px 24px;border-radius:6px;min-width:320px;max-width:520px}
#confirm .row{margin-top:16px;text-align:right}
</style>
</head>
<body>
<div id="banners"></div>
<header>
  <h1>AEOS Door Console</h1>
  <span id="aeos-url"></span>
  <span id="login-box">
    <input type="text" id="user" placeholder="AEOS user" autocomplete="off">
    <input type="password" id="password" placeholder="Password" autocomplete="off">
    <button id="btn-login">Log in</button>
  </span>
  <span id="logout-box" style="display:none"><span id="login-state"></span> <button id="btn-logout">Log out</button></span>
  <span id="login-msg"></span>
</header>
<nav>
  <button class="tab active" data-tab="doors">Doors</button>
  <button class="tab" data-tab="setup">Setup</button>
  <button class="tab" data-tab="raw">Raw call</button>
  <button class="tab" data-tab="audit">Audit</button>
  <button class="tab" data-tab="debug">Debug</button>
</nav>

<div class="panel active" id="tab-doors">
  <button id="btn-load-doors">Load doors</button>
  <input type="text" id="door-filter" placeholder="Filter doors">
  <div class="msg" id="doors-msg"></div>
  <table><thead id="doors-head"></thead><tbody id="doors-body"></tbody></table>
</div>

<div class="panel" id="tab-setup">
  <fieldset><legend>Connection</legend>
    <label><span>AEOS URL</span><input type="text" id="cfg-aeosUrl" size="46"></label>
    <label><span>WSDL URL (empty = AEOS URL + ?wsdl)</span><input type="text" id="cfg-wsdlUrl" size="46"></label><br>
    <label><span>SOAP version</span><select id="cfg-soapVersion"><option>1.1</option><option>1.2</option></select></label>
    <label><span>Authentication</span><select id="cfg-auth"><option value="basic">HTTP Basic</option><option value="wsse">WS-Security UsernameToken</option></select></label>
    <label><span>Timeout (s)</span><input type="number" id="cfg-timeoutSec" min="1" max="600" style="width:80px"></label>
    <label><span>Namespace prefix</span><input type="text" id="cfg-namespacePrefix" size="8"></label>
    <label><span>Target namespace</span><input type="text" id="cfg-targetNamespace" size="40"></label><br>
    <label><input type="checkbox" id="cfg-tlsSkipValidation"> Skip TLS certificate validation (self-signed server; shows a warning)</label><br>
    <label><span>Audit file (empty = default)</span><input type="text" id="cfg-auditFile" size="40"></label>
    <label><span>Debug log file (empty = default)</span><input type="text" id="cfg-debugLogFile" size="40"></label>
    <label><span>Debug level</span><select id="cfg-debugLevel"><option>full</option><option>basic</option></select></label>
  </fieldset>
  <p><button id="btn-load-wsdl">Load WSDL</button> <span id="wsdl-status"></span></p>
  <div id="setup-actions"></div>
  <div class="setup-bar">
  <p>
    <button id="btn-save">Save</button>
    <button id="btn-test-list">Test list (uses saved settings)</button>
  </p>
  <div class="msg" id="setup-msg"></div>
  </div>
  <pre id="test-list-out" style="display:none"></pre>
</div>

<div class="panel" id="tab-raw">
  <p>
    <button id="btn-raw-load">Load operations (WSDL)</button>
    <label><span>Operation</span><select id="raw-op"></select></label>
    <label><span>SOAP action</span><input type="text" id="raw-soapaction" size="40"></label>
  </p>
  <label style="display:block"><span>Request body (XML inside the SOAP Body; placeholders {{ns}} {{tns}} work)</span>
  <textarea id="raw-body"></textarea></label>
  <p><button id="btn-raw-send">Send</button></p>
  <div class="msg" id="raw-msg"></div>
  <pre id="raw-out"></pre>
</div>

<div class="panel" id="tab-audit">
  <button id="btn-audit-refresh">Refresh</button> <span id="audit-chain"></span>
  <div class="msg" id="audit-msg"></div>
  <table><thead><tr><th>Time (UTC)</th><th>Windows user</th><th>AEOS user</th><th>Action</th><th>Door</th><th>HTTP</th><th>OK</th><th>Fault</th></tr></thead>
  <tbody id="audit-body"></tbody></table>
</div>

<div class="panel" id="tab-debug">
  <button id="btn-dl-log">Download debug log</button>
  <button id="btn-diag">Create diagnostics zip</button>
  <span id="diag-out"></span>
  <div class="msg" id="debug-msg"></div>
  <p style="font-size:12px;color:#52606f">Refreshes every 3 seconds while this tab is open. File: <span id="debug-file"></span></p>
  <pre id="debug-out"></pre>
</div>

<div id="confirm" role="dialog" aria-modal="true">
  <div class="box"><div id="confirm-msg"></div>
  <div class="row"><button id="confirm-cancel">Cancel</button> <button id="confirm-ok">OK</button></div></div>
</div>

<script>
(function(){
'use strict';
var TOKEN=document.querySelector('meta[name="console-token"]').getAttribute('content');
var ACTIONS=['listDoors','lock','unlock','access'];
var CFG=null,OPS=[],DOORS=[],debugTimer=null;
function $(id){return document.getElementById(id);}
function h(tag,attrs,kids){
  var e=document.createElement(tag);
  if(attrs){Object.keys(attrs).forEach(function(k){
    if(k==='text'){e.textContent=attrs[k];}else if(k==='class'){e.className=attrs[k];}else{e.setAttribute(k,attrs[k]);}
  });}
  (kids||[]).forEach(function(c){e.appendChild(typeof c==='string'?document.createTextNode(c):c);});
  return e;
}
function api(method,path,body){
  var opt={method:method,headers:{'X-Console-Token':TOKEN}};
  if(body!==undefined){opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(body);}
  return fetch(path,opt).then(function(r){
    return r.text().then(function(txt){
      var j=null;try{j=JSON.parse(txt);}catch(e){}
      var rid=(j&&j.requestId)||r.headers.get('X-Request-Id')||'-';
      if(!r.ok){
        var er=new Error((j&&j.error&&j.error.message)||('HTTP '+r.status));
        er.rid=rid;er.code=(j&&j.error&&j.error.code)||'';throw er;
      }
      j=j||{};j._rid=rid;return j;
    });
  },function(e){var er=new Error('Cannot reach the console process: '+e.message);er.rid='-';throw er;});
}
function errText(e){return e.message+' (request id '+(e.rid||'-')+')';}
function setMsg(id,text,cls){var m=$(id);m.textContent=text||'';m.className='msg'+(cls?' '+cls:'');}
function download(path,fname){
  return fetch(path,{headers:{'X-Console-Token':TOKEN}}).then(function(r){
    if(!r.ok){throw new Error('HTTP '+r.status+' (request id '+(r.headers.get('X-Request-Id')||'-')+')');}
    return r.blob();
  }).then(function(b){
    var u=URL.createObjectURL(b);var a=h('a',{href:u,download:fname});
    document.body.appendChild(a);a.click();a.remove();
    setTimeout(function(){URL.revokeObjectURL(u);},5000);
  });
}

/* ---- confirm dialog (no alert/confirm) ---- */
function confirmDialog(msg){
  return new Promise(function(res){
    var d=$('confirm');$('confirm-msg').textContent=msg;d.style.display='flex';$('confirm-ok').focus();
    function done(v){d.style.display='none';$('confirm-ok').onclick=null;$('confirm-cancel').onclick=null;res(v);}
    $('confirm-ok').onclick=function(){done(true);};
    $('confirm-cancel').onclick=function(){done(false);};
  });
}

/* ---- tabs ---- */
function showTab(name){
  Array.prototype.forEach.call(document.querySelectorAll('.tab'),function(b){b.classList.toggle('active',b.getAttribute('data-tab')===name);});
  Array.prototype.forEach.call(document.querySelectorAll('.panel'),function(p){p.classList.toggle('active',p.id==='tab-'+name);});
  if(debugTimer){clearInterval(debugTimer);debugTimer=null;}
  if(name==='audit'){loadAudit();}
  if(name==='debug'){loadDebug();debugTimer=setInterval(loadDebug,3000);}
}
Array.prototype.forEach.call(document.querySelectorAll('.tab'),function(b){b.onclick=function(){showTab(b.getAttribute('data-tab'));};});

/* ---- header / session / banners ---- */
function renderBanners(){
  var b=$('banners');b.innerHTML='';
  if(CFG&&CFG.tlsSkipValidation){b.appendChild(h('div',{class:'warn',text:'WARNING: TLS certificate validation is OFF. The AEOS server identity is not checked.'}));}
  if(CFG&&/^http:/i.test(CFG.aeosUrl||'')){b.appendChild(h('div',{class:'warn',text:'WARNING: the AEOS URL is plain http. The password is sent unencrypted.'}));}
  $('aeos-url').textContent=(CFG&&CFG.aeosUrl)?CFG.aeosUrl:'(AEOS URL not set - open Setup)';
}
function renderSession(s){
  $('login-box').style.display=s.loggedIn?'none':'';
  $('logout-box').style.display=s.loggedIn?'':'none';
  $('login-state').textContent=s.loggedIn?('logged in as '+s.user):'';
}
$('btn-login').onclick=function(){
  setMsg('login-msg','');
  api('POST','/api/v1/login',{user:$('user').value,password:$('password').value}).then(function(r){
    $('password').value='';renderSession(r);
  }).catch(function(e){$('login-msg').textContent=errText(e);});
};
$('password').onkeydown=function(ev){if(ev.key==='Enter'){$('btn-login').click();}};
$('btn-logout').onclick=function(){api('POST','/api/v1/logout').then(renderSession).catch(function(e){$('login-msg').textContent=errText(e);});};

/* ---- doors ---- */
function renderDoors(){
  var extras=(CFG&&CFG.actions.listDoors.extraFields)||[];
  var head=$('doors-head');head.innerHTML='';
  var tr=h('tr',null,[h('th',{text:'Name'}),h('th',{text:'Id'})]);
  extras.forEach(function(x){tr.appendChild(h('th',{text:x}));});
  tr.appendChild(h('th',{text:'Actions'}));tr.appendChild(h('th',{text:'Result'}));head.appendChild(tr);
  var body=$('doors-body');body.innerHTML='';
  var f=$('door-filter').value.toLowerCase();
  DOORS.forEach(function(d){
    if(f&&(d.name+' '+d.id).toLowerCase().indexOf(f)<0){return;}
    var row=h('tr',{'data-id':d.id},[h('td',{text:d.name}),h('td',{text:d.id})]);
    extras.forEach(function(x){row.appendChild(h('td',{text:(d.extra&&d.extra[x])||''}));});
    var acts=h('td');var res=h('td',{class:'result'});
    ['lock','unlock','access'].forEach(function(a){
      var def=CFG.actions[a];if(!def||!def.operation){return;}
      var btn=h('button',{class:'act','data-action':a,text:def.label||a});
      btn.onclick=function(){runAction(a,d,btn,res);};
      acts.appendChild(btn);
    });
    row.appendChild(acts);row.appendChild(res);body.appendChild(row);
  });
}
function runAction(a,d,btn,res){
  var def=CFG.actions[a];
  var p=(def.confirm===false)?Promise.resolve(true):confirmDialog((def.label||a)+' door "'+d.name+'" ('+d.id+')?');
  p.then(function(ok){
    if(!ok){return;}
    btn.disabled=true;res.className='result';res.textContent='working...';
    return api('POST','/api/v1/doors/action',{action:a,id:d.id,name:d.name}).then(function(r){
      res.setAttribute('data-rid',r._rid);
      res.className='result '+(r.ok?'ok':'bad');
      res.textContent=r.ok?('OK (HTTP '+r.httpStatus+') request id '+r._rid):('FAILED: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')');
    }).catch(function(e){
      res.setAttribute('data-rid',e.rid||'-');res.className='result bad';res.textContent='FAILED: '+errText(e);
    }).then(function(){btn.disabled=false;});
  });
}
$('btn-load-doors').onclick=function(){
  setMsg('doors-msg','Loading...');
  api('GET','/api/v1/doors').then(function(r){
    DOORS=r.doors||[];renderDoors();
    if(r.ok){setMsg('doors-msg',DOORS.length+' door(s) loaded (request id '+r._rid+')','good');}
    else{setMsg('doors-msg','AEOS answered with an error: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')','bad');}
  }).catch(function(e){DOORS=[];renderDoors();setMsg('doors-msg',errText(e),'bad');});
};
$('door-filter').oninput=renderDoors;

/* ---- setup ---- */
function fillOps(sel,current){
  var keep=current!==undefined?current:sel.value;
  sel.innerHTML='';sel.appendChild(h('option',{value:'',text:'(not mapped)'}));
  var found=false;
  OPS.forEach(function(o){sel.appendChild(h('option',{value:o.name,text:o.name}));if(o.name===keep){found=true;}});
  if(keep&&!found){sel.appendChild(h('option',{value:keep,text:keep}));}
  sel.value=keep||'';
}
function opByName(n){for(var i=0;i<OPS.length;i++){if(OPS[i].name===n){return OPS[i];}}return null;}
function lbl(text,el){return h('label',null,[h('span',{text:text}),el]);}
function buildSetupActions(){
  var box=$('setup-actions');box.innerHTML='';
  ACTIONS.forEach(function(a){
    var fs=h('fieldset',{id:'fs-'+a},[h('legend',{text:a==='listDoors'?'List doors (listDoors)':('Action: '+a)})]);
    if(a!=='listDoors'){
      fs.appendChild(lbl('Button label',h('input',{type:'text',id:'lbl-'+a,size:'18'})));
      fs.appendChild(h('label',null,[h('input',{type:'checkbox',id:'conf-'+a}),' Ask for confirmation']));
    }
    var sel=h('select',{id:'op-'+a});
    sel.onchange=function(){var o=opByName(sel.value);if(o){$('sa-'+a).value=o.soapAction||'';}};
    fs.appendChild(lbl('WSDL operation',sel));
    fs.appendChild(lbl('SOAP action',h('input',{type:'text',id:'sa-'+a,size:'40'})));
    var sk=h('button',{id:'skel-'+a,text:'Insert skeleton'});
    sk.onclick=function(){var o=opByName($('op-'+a).value);if(o){$('body-'+a).value=o.skeleton;}else{setMsg('setup-msg','Select an operation (Load WSDL first) to insert its skeleton.','bad');}};
    fs.appendChild(sk);
    fs.appendChild(h('label',{style:'display:block'},[h('span',{text:'Request body template ({{id}} {{name}} {{ns}} {{tns}})'}),h('textarea',{id:'body-'+a})]));
    if(a==='listDoors'){
      fs.appendChild(lbl('Door element',h('input',{type:'text',id:'itemElement',size:'18'})));
      fs.appendChild(lbl('Id field',h('input',{type:'text',id:'idField',size:'18'})));
      fs.appendChild(lbl('Name field',h('input',{type:'text',id:'nameField',size:'18'})));
      fs.appendChild(lbl('Extra columns (comma separated)',h('input',{type:'text',id:'extraFields',size:'28'})));
    }
    box.appendChild(fs);
  });
}
function fillSetup(){
  $('cfg-aeosUrl').value=CFG.aeosUrl;$('cfg-wsdlUrl').value=CFG.wsdlUrl;$('cfg-soapVersion').value=CFG.soapVersion;
  $('cfg-auth').value=CFG.auth;$('cfg-timeoutSec').value=CFG.timeoutSec;$('cfg-namespacePrefix').value=CFG.namespacePrefix;
  $('cfg-targetNamespace').value=CFG.targetNamespace;$('cfg-tlsSkipValidation').checked=!!CFG.tlsSkipValidation;
  $('cfg-auditFile').value=CFG.auditFile;$('cfg-debugLogFile').value=CFG.debugLogFile;$('cfg-debugLevel').value=CFG.debugLevel;
  ACTIONS.forEach(function(a){
    var o=CFG.actions[a];fillOps($('op-'+a),o.operation);$('sa-'+a).value=o.soapAction;$('body-'+a).value=o.body;
    if(a!=='listDoors'){$('lbl-'+a).value=o.label;$('conf-'+a).checked=(o.confirm!==false);}
  });
  var l=CFG.actions.listDoors;$('itemElement').value=l.itemElement;$('idField').value=l.idField;$('nameField').value=l.nameField;
  $('extraFields').value=(l.extraFields||[]).join(', ');
}
function readSetup(){
  var c=JSON.parse(JSON.stringify(CFG));
  c.aeosUrl=$('cfg-aeosUrl').value.trim();c.wsdlUrl=$('cfg-wsdlUrl').value.trim();c.soapVersion=$('cfg-soapVersion').value;
  c.auth=$('cfg-auth').value;c.timeoutSec=parseInt($('cfg-timeoutSec').value,10)||30;c.namespacePrefix=$('cfg-namespacePrefix').value.trim();
  c.targetNamespace=$('cfg-targetNamespace').value.trim();c.tlsSkipValidation=$('cfg-tlsSkipValidation').checked;
  c.auditFile=$('cfg-auditFile').value.trim();c.debugLogFile=$('cfg-debugLogFile').value.trim();c.debugLevel=$('cfg-debugLevel').value;
  ACTIONS.forEach(function(a){
    var o=c.actions[a];o.operation=$('op-'+a).value;o.soapAction=$('sa-'+a).value;o.body=$('body-'+a).value;
    if(a!=='listDoors'){o.label=$('lbl-'+a).value;o.confirm=$('conf-'+a).checked;}
  });
  var l=c.actions.listDoors;l.itemElement=$('itemElement').value.trim();l.idField=$('idField').value.trim();l.nameField=$('nameField').value.trim();
  l.extraFields=$('extraFields').value.split(',').map(function(s){return s.trim();}).filter(function(s){return s;});
  return c;
}
/* Save what is on the Setup tab, then reload it from the server (header, banners, doors follow). */
function saveSetup(){
  return api('PUT','/api/v1/config',readSetup()).then(function(r){
    return api('GET','/api/v1/config').then(function(c){CFG=c;fillSetup();renderBanners();renderDoors();return r;});
  });
}
function byOpName(a,b){var x=a.name.toLowerCase(),y=b.name.toLowerCase();return x<y?-1:(x>y?1:0);}
/* Load WSDL works on what is on screen: it saves the Setup first, lists the operations A-Z, and saves
   again so the target namespace and SOAP version it found are kept. show(text, cls) reports progress. */
function loadWsdl(show){
  show('Saving settings, loading WSDL...','');
  saveSetup().then(function(){
    api('GET','/api/v1/wsdl').then(function(r){
      OPS=(r.operations||[]).slice().sort(byOpName);
      ACTIONS.forEach(function(a){fillOps($('op-'+a));});fillOps($('raw-op'));
      if(r.targetNamespace&&!$('cfg-targetNamespace').value){$('cfg-targetNamespace').value=r.targetNamespace;}
      if(r.soapVersion){$('cfg-soapVersion').value=r.soapVersion;}
      var done=OPS.length+' operations loaded (A-Z), target namespace "'+r.targetNamespace+'", SOAP '+r.soapVersion+' (request id '+r._rid+')';
      saveSetup().then(function(){show(done,'good');}).catch(function(e){show(done+' - but not saved: '+errText(e),'bad');});
    }).catch(function(e){show('WSDL failed: '+errText(e),'bad');});
  }).catch(function(e){show('Not saved, so the WSDL was not loaded: '+errText(e),'bad');});
}
$('btn-load-wsdl').onclick=function(){loadWsdl(function(t,c){var s=$('wsdl-status');s.textContent=t;s.className=c||'';});};
$('btn-save').onclick=function(){
  setMsg('setup-msg','Saving...');
  saveSetup().then(function(r){setMsg('setup-msg','Saved (request id '+r._rid+')','good');})
    .catch(function(e){setMsg('setup-msg','Not saved: '+errText(e),'bad');});
};
$('btn-test-list').onclick=function(){
  var out=$('test-list-out');out.style.display='none';setMsg('setup-msg','Testing...');
  api('GET','/api/v1/doors').then(function(r){
    out.style.display='';out.textContent=r.raw||'';
    if(r.ok){setMsg('setup-msg','Parsed '+(r.doors||[]).length+' door(s) (request id '+r._rid+')','good');}
    else{setMsg('setup-msg','AEOS answered with an error: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')','bad');}
  }).catch(function(e){setMsg('setup-msg',errText(e),'bad');});
};

/* ---- raw call ---- */
$('btn-raw-load').onclick=function(){loadWsdl(function(t,c){setMsg('raw-msg',t,c);});};
$('raw-op').onchange=function(){
  var o=opByName($('raw-op').value);
  if(o){$('raw-soapaction').value=o.soapAction||'';if(!$('raw-body').value){$('raw-body').value=o.skeleton;}}
};
$('btn-raw-send').onclick=function(){
  setMsg('raw-msg','Sending...');$('raw-out').textContent='';
  api('POST','/api/v1/call',{operation:$('raw-op').value,soapAction:$('raw-soapaction').value,body:$('raw-body').value}).then(function(r){
    var t='HTTP '+r.httpStatus+(r.fault?('\nSOAP FAULT: '+r.fault):'')+'\n\n'+(r.response||'');
    $('raw-out').textContent=t;
    if(r.ok){setMsg('raw-msg','OK (request id '+r._rid+')','good');}
    else{setMsg('raw-msg','Fault or error: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')','bad');}
  }).catch(function(e){setMsg('raw-msg',errText(e),'bad');});
};

/* ---- audit ---- */
function loadAudit(){
  api('GET','/api/v1/audit?limit=50').then(function(r){
    var b=$('audit-body');b.innerHTML='';
    (r.records||[]).slice().reverse().forEach(function(x){
      b.appendChild(h('tr',null,[h('td',{text:x.ts}),h('td',{text:x.windowsUser}),h('td',{text:x.aeosUser}),h('td',{text:x.action}),
        h('td',{text:(x.doorName||'')+' ('+(x.doorId||'')+')'}),h('td',{text:String(x.httpStatus)}),h('td',{text:x.ok?'yes':'NO'}),h('td',{text:x.fault||''})]));
    });
    var c=$('audit-chain');c.textContent=r.chainOk?('Chain OK ('+r.total+' records)'):('CHAIN BROKEN at record '+(r.badIndex+1));
    c.className=r.chainOk?'msg good':'msg bad';setMsg('audit-msg','');
  }).catch(function(e){setMsg('audit-msg',errText(e),'bad');});
}
$('btn-audit-refresh').onclick=loadAudit;

/* ---- debug ---- */
function loadDebug(){
  api('GET','/api/v1/debuglog?lines=300').then(function(r){
    var o=$('debug-out');var atEnd=(o.scrollTop+o.clientHeight>=o.scrollHeight-20);
    o.textContent=(r.lines||[]).join('\n');$('debug-file').textContent=r.file||'';
    if(atEnd){o.scrollTop=o.scrollHeight;}setMsg('debug-msg','');
  }).catch(function(e){setMsg('debug-msg',errText(e),'bad');});
}
$('btn-dl-log').onclick=function(){
  download('/api/v1/debuglog/download','aeos-console-debug.log').catch(function(e){setMsg('debug-msg','Download failed: '+e.message,'bad');});
};
$('btn-diag').onclick=function(){
  setMsg('debug-msg','Creating diagnostics zip...');
  api('POST','/api/v1/diagnostics',{}).then(function(r){
    var o=$('diag-out');o.innerHTML='';
    o.appendChild(h('span',{id:'diag-path',text:r.path}));o.appendChild(document.createTextNode(' '));
    var a=h('a',{href:'#',id:'diag-link',text:'Download'});
    a.onclick=function(ev){ev.preventDefault();download('/api/v1/diagnostics/download?file='+encodeURIComponent(r.fileName),r.fileName).catch(function(e){setMsg('debug-msg','Download failed: '+e.message,'bad');});};
    o.appendChild(a);setMsg('debug-msg','Diagnostics zip created (request id '+r._rid+'). Send it to the integrator.','good');
  }).catch(function(e){setMsg('debug-msg',errText(e),'bad');});
};

/* ---- start ---- */
buildSetupActions();
api('GET','/api/v1/config').then(function(c){
  CFG=c;fillSetup();renderBanners();renderDoors();
  return api('GET','/api/v1/session');
}).then(renderSession).catch(function(e){
  $('banners').appendChild(h('div',{class:'err',text:'Startup failed: '+errText(e)}));
});
})();
</script>
</body>
</html>
'@

# ============================================================================
# Main
# ============================================================================

function Start-Console {
    if (-not $ConfigFile) { $script:ConfigPath = Join-Path $script:ScriptDir 'aeos-console.json' }
    else { $script:ConfigPath = [System.IO.Path]::GetFullPath($ConfigFile) }
    $script:Port = $Port
    $script:Cred = $null
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $script:Token = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')

    $script:Config = Import-ConfigFile -Path $script:ConfigPath
    $problems = @(Test-ConfigObject $script:Config)
    Initialize-Paths
    $url = 'http://localhost:' + $Port + '/'
    Write-StartupBlock -Url $url
    foreach ($p in $problems) { Write-DebugLog 'startup' ('Config problem: ' + $p) 'WARN'; Write-Host ('Config problem: ' + $p) }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($url)
    try { $listener.Start() }
    catch {
        Write-DebugLog 'startup' ('Cannot listen on ' + $url + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
        Write-Host ('Cannot listen on ' + $url + ': ' + $_.Exception.Message)
        Write-Host 'Is another copy running? Use -Port to pick another port.'
        exit 1
    }
    Write-Host ('AEOS Door Console ' + $script:Version + ' listening on ' + $url + '  (Ctrl+C stops it)')
    Write-Host ('Config:    ' + $script:ConfigPath)
    Write-Host ('Debug log: ' + $script:DebugLogPath)
    Write-Host ('Audit:     ' + $script:AuditPath)
    if (-not $NoBrowser) { try { Start-Process $url } catch { Write-Host ('Could not open the browser: ' + $_.Exception.Message) } }
    try {
        while ($listener.IsListening) {
            $task = $listener.GetContextAsync()
            while (-not $task.Wait(500)) { }
            Invoke-Request -Ctx $task.Result
        }
    }
    finally {
        Write-DebugLog 'shutdown' 'Console stopping.'
        $listener.Stop()
        $listener.Close()
    }
}

Start-Console
