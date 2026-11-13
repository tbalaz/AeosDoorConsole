<#
.SYNOPSIS
    DoorKeeper by IT42 - local web page that forwards calls to a Nedap AEOS SOAP web service.

.DESCRIPTION
    Single self-contained Windows PowerShell 5.1 script. Serves http://localhost:<Port>/ (HttpListener,
    localhost only) with an embedded page (no CDN, works offline). Lists doors and offers lock / unlock /
    provide access per door. No AEOS operation names are built in: the operator maps each action to a WSDL
    operation and a request template on the Setup tab.

    Security: per-start random token (meta tag, header X-Console-Token on /api/v1/*), Origin check,
    AEOS password kept in memory only (PSCredential), never logged or written. Certificate validation
    can be skipped per request only (compiled callback), never globally. Every door action is written to
    a hash-chained audit file. A thorough debug log (doorkeeper-debug.log) is always on.

.PARAMETER ConfigFile
    Site config. Default: doorkeeper.json next to the script (created from cleared defaults if missing). If it is missing and
    aeos-console.json (the old name) exists next to the script, that file is used.

.PARAMETER LicenseFile
    License file. Default: license.json in the folder of the config file. Without a license file the console
    runs a 30-day trial counted from the first start (first-start date in trial.json, same folder).

.PARAMETER Port
    Local port. Default 8765.

.PARAMETER NoBrowser
    Do not open the default browser.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\DoorKeeper.ps1
    powershell -ExecutionPolicy Bypass -File .\DoorKeeper.ps1 -Port 9000 -NoBrowser
#>
[CmdletBinding()]
param(
    [string]$ConfigFile = '',
    [string]$LicenseFile = '',
    [int]$Port = 8765,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$script:Version = '1.0.0'
# ---- License constants: the product rename is ONE edit here ------------------------------------------------------
# $script:LicenseProductId must equal the "product" field of every issued license (tools\New-License.ps1 $ProductId).
# $script:LicensePublicKeyXml is the public half of the signing key (same text as tools\license-public-key.xml).
$script:LicenseProductId = 'DoorKeeper'
$script:LicensePublicKeyXml = '<RSAKeyValue><Modulus>0b9MUB0Iyk066tBoQ+AGwP+QeC6wncUgZjZ73U8Mb8F/i066yp90NRD3obyoxdqUNv6ZfVY8Gv9xElOk7UkTiNfMXnIrt4DUrgNC+s1Z6Ul0wvMoDFuLgK+Kwqed23aI1LVVXY6EeF5uhMe3ddTemgm7N9J56cfmPLcjciOO/s6XexmwdOBw4vvt9XUK8k26ExBdm3bAkIP6/A7DymCc8UKqAU5/ALzRkp4VTQ4AEqCKfFKfqJ4zuYofCpqujhgivFzIc/Kf6EdjIQM3C++7w6Ba3cdTmiIoL8hbDUvJeIMQhRj4aEirxC9OGnzPAtxkzdsih6j93T6iDnVRcS9D3GVxV8OZ2WeFIDOUhaR9mp1Gi2HvzH7pTyvHQ2w19RME8k1e/z5LqlNEHwpUaa03bXbeZannhIo51jzD7ZmPHHTzLtZdahyzOtVqPPbOUK5hVnAQq9gDPYvC79CkrFkZt1p1Ya1ZsZFIdeleM/G/TXdMS8nGxfAlh2r0TlxjyZRV</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
$script:TrialDays = 30
# ------------------------------------------------------------------------------------------------------------------
$script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:ZeroHash = ('0' * 64)
$script:ActionNames = @('listDoors', 'lock', 'unlock', 'access', 'normal')

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

function Get-SocketForbiddenChars {
    # Characters that must never be part of a substituted value in a socket command (injection guard).
    # The user name and password additionally may not hold a comma or a closing parenthesis.
    # A door token outside double quotes in the template (-Unquoted) may not hold a comma or any parenthesis:
    # there they would split or close the argument list. An opening parenthesis is refused only in unquoted
    # door tokens, never in the user name or password (it cannot split or close an argument there).
    param([bool]$Credential = $false, [bool]$Unquoted = $false)
    $c = @("`r", "`n", '"', ';')
    if ($Credential -or $Unquoted) { $c += @(',', ')') }
    if ($Unquoted -and -not $Credential) { $c += '(' }
    return $c
}

function Expand-SocketTemplate {
    # Single-pass replacement of {{id}} {{name}} {{<extra column>}} and, with -Login, {{user}} {{password}}.
    # No escaping: a substituted value holding a forbidden character REFUSES the whole command (Error set,
    # Text empty). Unknown tokens stay as they are. Returns an object with Text and Error.
    param([string]$Template, [string]$Id = '', [string]$Name = '', $Extra = $null, [string]$User = '', [string]$Password = '', [switch]$Login)
    $res = [pscustomobject]@{ Text = ''; Error = $null }
    if ($null -eq $Template) { return $res }
    $values = @{}
    if ($Extra -is [System.Collections.IDictionary]) {
        foreach ($k in $Extra.Keys) { $values[[string]$k] = [string]$Extra[$k] }
    }
    elseif ($null -ne $Extra) {
        foreach ($p in $Extra.PSObject.Properties) { $values[$p.Name] = [string]$p.Value }
    }
    $values['id'] = $Id
    $values['name'] = $Name
    $cred = @{}
    if ($Login) {
        $values['user'] = $User
        $values['password'] = $Password
        $cred['user'] = $true
        $cred['password'] = $true
    }
    $names = @{ "`r" = 'CR'; "`n" = 'LF'; '"' = 'double quote'; ';' = 'semicolon'; ',' = 'comma'; '(' = 'opening parenthesis'; ')' = 'closing parenthesis' }
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    # Double quotes seen in the template text so far; odd = the next token sits inside a quoted string.
    # Substituted values can never add a quote (it is forbidden), so only the template text counts.
    $quotes = 0
    foreach ($m in [System.Text.RegularExpressions.Regex]::Matches($Template, '\{\{([A-Za-z_][A-Za-z0-9_.\-]*)\}\}')) {
        $lit = $Template.Substring($pos, $m.Index - $pos)
        [void]$sb.Append($lit)
        $quotes += ($lit.Length - $lit.Replace('"', '').Length)
        $pos = $m.Index + $m.Length
        $key = $m.Groups[1].Value
        if (-not $values.ContainsKey($key)) { [void]$sb.Append($m.Value); continue }
        $v = [string]$values[$key]
        $unquoted = (($quotes % 2) -eq 0)
        $chars = @(Get-SocketForbiddenChars -Credential ($cred.ContainsKey($key)) -Unquoted $unquoted)
        $bad = @()
        foreach ($ch in $chars) { if ($v.IndexOf([char]$ch) -ge 0) { $bad += $names[[string]$ch] } }
        if ($bad.Count -gt 0) {
            $hint = ''
            $splitBad = @($bad | Where-Object { $_ -like '*comma*' -or $_ -like '*parenthesis*' })
            if ($unquoted -and $splitBad.Count -gt 0 -and -not $cred.ContainsKey($key)) { $hint = ' Put {{' + $key + '}} inside double quotes in the template to allow a comma or parentheses.' }
            $res.Error = 'The value of {{' + $key + '}} contains a character that is not allowed in a socket command (' + ($bad -join ', ') +
                '). Nothing was sent.' + $hint
            return $res
        }
        [void]$sb.Append($v)
    }
    [void]$sb.Append($Template.Substring($pos))
    $res.Text = $sb.ToString()
    return $res
}

function ConvertTo-VisibleControl {
    # Makes control characters visible for the log: <CR> <LF> <ETX> <0xNN>.
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int]$ch
        if ($c -eq 13) { [void]$sb.Append('<CR>') }
        elseif ($c -eq 10) { [void]$sb.Append('<LF>') }
        elseif ($c -eq 3) { [void]$sb.Append('<ETX>') }
        elseif ($c -lt 32) { [void]$sb.Append(('<0x{0:X2}>' -f $c)) }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function Get-SocketTerminatorText {
    param([string]$Terminator)
    if ($Terminator -eq 'LF') { return "`n" }
    return "`r`n"
}

function Resolve-SocketHost {
    # The socket host from the config, or the host of the AEOS URL when empty ('' when neither gives one).
    param([string]$SocketHost, [string]$AeosUrl)
    if ($SocketHost) { return $SocketHost.Trim() }
    if ($AeosUrl) {
        try { return ([System.Uri]$AeosUrl).Host } catch { return '' }
    }
    return ''
}

function Split-SocketBuffer {
    # Splits received text on LF (a CR before it is dropped, so CR LF and LF terminators both work).
    # Returns Lines (complete lines) and Rest (an unfinished last line).
    param([string]$Buffer)
    $lines = New-Object System.Collections.Generic.List[string]
    $rest = $Buffer
    if ($null -eq $rest) { $rest = '' }
    $i = $rest.IndexOf("`n")
    while ($i -ge 0) {
        $line = $rest.Substring(0, $i)
        if ($line.EndsWith("`r")) { $line = $line.Substring(0, $line.Length - 1) }
        $lines.Add($line)
        $rest = $rest.Substring($i + 1)
        $i = $rest.IndexOf("`n")
    }
    return [pscustomobject]@{ Lines = $lines.ToArray(); Rest = $rest }
}

function Get-RegexError {
    # $null when the pattern compiles (or is empty), else the message.
    param([string]$Pattern)
    if (-not $Pattern) { return $null }
    try { [void](New-Object System.Text.RegularExpressions.Regex($Pattern)); return $null }
    catch { return $_.Exception.Message }
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
    # SHA256(prevHash|ts|windowsUser|aeosUser|action|doorId|doorName|httpStatus|ok[|batch]), hex, UTF-8.
    # The batch part is added only when the record has one, so records from before batches keep their hash.
    param([string]$PrevHash, [string]$Ts, [string]$WindowsUser, [string]$AeosUser, [string]$Action,
        [string]$DoorId, [string]$DoorName, [int]$HttpStatus, [bool]$Ok, [string]$Batch = '')
    $okText = 'false'
    if ($Ok) { $okText = 'true' }
    $parts = @($PrevHash, $Ts, $WindowsUser, $AeosUser, $Action, $DoorId, $DoorName, [string]$HttpStatus, $okText)
    if ($Batch) { $parts += $Batch }
    $s = $parts -join '|'
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
            -HttpStatus ([int]$r.httpStatus) -Ok ([bool]$r.ok) -Batch ([string]$r.batch)
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
  "socket": {
    "host": "",
    "port": 0,
    "tls": true,
    "tlsSkipValidation": false,
    "terminator": "CRLF",
    "greetingWaitMs": 2000,
    "loginTemplate": "",
    "loginSuccessPattern": "",
    "initCommands": [],
    "replyTimeoutSec": 10
  },
  "actions": {
    "listDoors": { "operation": "", "soapAction": "", "body": "", "itemElement": "", "idField": "", "nameField": "", "extraFields": [], "pageSize": 0 },
    "lock":   { "label": "Lock",           "transport": "soap", "operation": "", "soapAction": "", "body": "", "command": "", "successPattern": "", "confirm": true },
    "unlock": { "label": "Unlock",         "transport": "soap", "operation": "", "soapAction": "", "body": "", "command": "", "successPattern": "", "confirm": true },
    "access": { "label": "Provide access", "transport": "soap", "operation": "", "soapAction": "", "body": "", "command": "", "successPattern": "", "confirm": true },
    "normal": { "label": "Normal",         "transport": "soap", "operation": "", "soapAction": "", "body": "", "command": "", "successPattern": "", "confirm": true }
  },
  "doorState": {
    "checks": [],
    "otherwiseLabel": "",
    "maxDoorsPerRefresh": 500
  },
  "locations": { "levels": [], "rules": [], "map": {}, "labels": {} },
  "groups": [],
  "arming": { "armAction": "lock", "disarmAction": "normal", "armLabel": "Arm", "disarmLabel": "Disarm" }
}
'@
}

function Merge-Config {
    # Default keys only; loaded values win; arrays stay arrays; unknown keys are dropped (an empty default object keeps every loaded key).
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
        if ($dv -is [System.Management.Automation.PSCustomObject] -and @($dv.PSObject.Properties).Count -eq 0) {
            # an empty default object is a free-form map (locations.map, locations.labels): the loaded keys stay
            if ($has -and $lv -is [System.Management.Automation.PSCustomObject]) { $out[$name] = $lv } else { $out[$name] = $dv }
        }
        elseif ($dv -is [System.Management.Automation.PSCustomObject]) {
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
    foreach ($a in @('listDoors', 'lock', 'unlock', 'access', 'normal')) {
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
    $sk = $Config.socket
    if ($null -eq $sk) { $errs.Add('socket section is missing.') }
    else {
        if ($sk.tls -isnot [bool]) { $errs.Add('socket.tls must be true or false.') }
        if ($sk.tlsSkipValidation -isnot [bool]) { $errs.Add('socket.tlsSkipValidation must be true or false.') }
        if (@('CRLF', 'LF') -notcontains [string]$sk.terminator) { $errs.Add('socket.terminator must be CRLF or LF.') }
        $sp = 0
        if (-not [int]::TryParse([string]$sk.port, [ref]$sp) -or $sp -lt 0 -or $sp -gt 65535) { $errs.Add('socket.port must be a number from 0 to 65535.') }
        $sg = 0
        if (-not [int]::TryParse([string]$sk.greetingWaitMs, [ref]$sg) -or $sg -lt 0 -or $sg -gt 60000) { $errs.Add('socket.greetingWaitMs must be a number from 0 to 60000.') }
        $sr = 0
        if (-not [int]::TryParse([string]$sk.replyTimeoutSec, [ref]$sr) -or $sr -lt 1 -or $sr -gt 120) { $errs.Add('socket.replyTimeoutSec must be a number from 1 to 120.') }
        if ([string]$sk.host -and [string]$sk.host -notmatch '^[A-Za-z0-9._\-]+$|^\[[0-9A-Fa-f:.]+\]$') { $errs.Add('socket.host must be a host name or IP address.') }
        $lpe = Get-RegexError ([string]$sk.loginSuccessPattern)
        if ($lpe) { $errs.Add('socket.loginSuccessPattern is not a valid regular expression: ' + $lpe) }
    }
    foreach ($a in @('lock', 'unlock', 'access', 'normal')) {
        $act = $Config.actions.$a
        if ($null -eq $act) { continue }
        if (@('soap', 'socket') -notcontains [string]$act.transport) { $errs.Add('actions.' + $a + '.transport must be soap or socket.'); continue }
        $spe = Get-RegexError ([string]$act.successPattern)
        if ($spe) { $errs.Add('actions.' + $a + '.successPattern is not a valid regular expression: ' + $spe) }
        if ([string]$act.transport -eq 'socket' -and $null -ne $sk) {
            if (-not [string]$act.command) { $errs.Add('actions.' + $a + ' uses the socket transport and needs a command.') }
            $pp = 0
            if (-not [int]::TryParse([string]$sk.port, [ref]$pp) -or $pp -lt 1 -or $pp -gt 65535) { $errs.Add('actions.' + $a + ' uses the socket transport: set socket.port (1-65535).') }
            if (-not (Resolve-SocketHost -SocketHost ([string]$sk.host) -AeosUrl ([string]$Config.aeosUrl))) { $errs.Add('actions.' + $a + ' uses the socket transport: set socket.host or the AEOS URL.') }
        }
    }
    $ds = $Config.doorState
    if ($null -eq $ds) { $errs.Add('doorState section is missing.') }
    else {
        $md = 0
        if (-not [int]::TryParse([string]$ds.maxDoorsPerRefresh, [ref]$md) -or $md -lt 1 -or $md -gt 5000) { $errs.Add('doorState.maxDoorsPerRefresh must be a number from 1 to 5000.') }
        $used = 0
        $ci = 0
        foreach ($c in @($ds.checks)) {
            $ci++
            if ($null -eq $c) { continue }
            $has = @([string]$c.label, [string]$c.command, [string]$c.matchPattern | Where-Object { $_ })
            if ($has.Count -eq 0) { continue }
            $used++
            if (-not [string]$c.label -or -not [string]$c.command -or -not [string]$c.matchPattern) { $errs.Add('doorState.checks[' + $ci + '] needs a label, a command and a match pattern.') }
            $mpe = Get-RegexError ([string]$c.matchPattern)
            if ($mpe) { $errs.Add('doorState.checks[' + $ci + '].matchPattern is not a valid regular expression: ' + $mpe) }
        }
        if ($used -gt 0 -and $null -ne $sk) {
            $pp = 0
            if (-not [int]::TryParse([string]$sk.port, [ref]$pp) -or $pp -lt 1 -or $pp -gt 65535) { $errs.Add('doorState uses the socket interface: set socket.port (1-65535).') }
            if (-not (Resolve-SocketHost -SocketHost ([string]$sk.host) -AeosUrl ([string]$Config.aeosUrl))) { $errs.Add('doorState uses the socket interface: set socket.host or the AEOS URL.') }
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
        $ps = 0
        if (-not [int]::TryParse([string]$ld.pageSize, [ref]$ps) -or $ps -lt 0 -or $ps -gt 100000) { $errs.Add('actions.listDoors.pageSize must be a whole number from 0 to 100000 (0 = one request).') }
        elseif ($ps -lt 1 -and ([string]$ld.body).Contains('{{start}}')) { $errs.Add('The list doors body uses {{start}}: set the page size (1-100000).') }
    }
    $lc = $Config.locations
    if ($null -ne $lc) {
        $seenLv = @{}
        foreach ($lv in @($lc.levels)) {
            $n = [string]$lv
            if ($n -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { $errs.Add('locations.levels: "' + $n + '" must be a plain name (letters, digits, _) because it is also a regex group name.'); continue }
            if ($seenLv.ContainsKey($n)) { $errs.Add('locations.levels: "' + $n + '" is listed twice.'); continue }
            $seenLv[$n] = $true
        }
        $ri = 0
        foreach ($r in @($lc.rules)) {
            $ri++
            if ($null -eq $r) { continue }
            if ([string]$r.source -notmatch $ncname) { $errs.Add('locations.rules[' + $ri + '].source must be name, id or the name of an extra column.') }
            $pat = [string]$r.pattern
            if (-not $pat) { $errs.Add('locations.rules[' + $ri + '] needs a pattern.') }
            else {
                $pe = Get-RegexError $pat
                if ($pe) { $errs.Add('locations.rules[' + $ri + '].pattern is not a valid regular expression: ' + $pe) }
                elseif ($pat -notmatch '\(\?<[A-Za-z_]') { $errs.Add('locations.rules[' + $ri + '].pattern needs at least one named group such as (?<city>[A-Z]+).') }
            }
        }
        if ($null -ne $lc.map) {
            if ($lc.map -isnot [System.Management.Automation.PSCustomObject]) { $errs.Add('locations.map must be an object of key -> { level: value }.') }
            else { foreach ($mp in $lc.map.PSObject.Properties) { if ($mp.Value -isnot [System.Management.Automation.PSCustomObject]) { $errs.Add('locations.map["' + $mp.Name + '"] must be an object of level -> value.') } } }
        }
        if ($null -ne $lc.labels -and $lc.labels -isnot [System.Management.Automation.PSCustomObject]) { $errs.Add('locations.labels must be an object of value -> display name.') }
    }
    $gi = 0
    $gseen = @{}
    foreach ($g in @($Config.groups)) {
        $gi++
        if ($null -eq $g) { continue }
        $gn = ([string]$g.name).Trim()
        if (-not $gn) { $errs.Add('groups[' + $gi + '] needs a name.') }
        elseif ($gseen.ContainsKey($gn.ToLowerInvariant())) { $errs.Add('groups: the name "' + $gn + '" is used twice.') }
        else { $gseen[$gn.ToLowerInvariant()] = $true }
        if ($null -ne $g.match -and $g.match -isnot [System.Management.Automation.PSCustomObject]) { $errs.Add('groups[' + $gi + '].match must be an object of level -> list of values.') }
    }
    $ar = $Config.arming
    if ($null -ne $ar) {
        foreach ($k in @('armAction', 'disarmAction')) {
            if (@('lock', 'unlock', 'access', 'normal') -notcontains [string]$ar.$k) { $errs.Add('arming.' + $k + ' must be lock, unlock, access or normal.') }
        }
        foreach ($k in @('armLabel', 'disarmLabel')) {
            if (-not ([string]$ar.$k).Trim()) { $errs.Add('arming.' + $k + ' must not be empty.') }
        }
    }
    return $errs.ToArray()
}

# ============================================================================
# Locations, door groups, arming report (the page carries a JS twin of placeDoor / doorInGroup; tests\fixtures\locations.json
# feeds both and must give the same result)
# ============================================================================

function Get-JsonProp {
    # Property or key of a parsed-JSON object or a dictionary; $null when missing.
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } else { return $null } }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-DoorLocation {
    # Places one door. $Door has id, name, extra. $Locations = the config object { levels, rules, map, labels }.
    # Rules in order, the first rule whose source value matches wins; every named group with a value becomes a field.
    # Then the map overrides: the first of id, name, extra values (in order) that is a key of the map; its values replace fields.
    # Path = the level values in order up to the first level without a value; no value for the first level = unplaced.
    param($Door, $Locations)
    $fields = [ordered]@{}
    $ruleNo = 0
    $levels = @()
    if ($null -ne $Locations) { $levels = @(@($Locations.levels) | Where-Object { $null -ne $_ -and [string]$_ } | ForEach-Object { [string]$_ }) }
    $extra = $null
    if ($null -ne $Door) { $extra = Get-JsonProp $Door 'extra' }
    $extraValues = @()
    if ($extra -is [System.Collections.IDictionary]) { foreach ($k in $extra.Keys) { $extraValues += [string]$extra[$k] } }
    elseif ($null -ne $extra) { foreach ($p in $extra.PSObject.Properties) { $extraValues += [string]$p.Value } }
    if ($null -ne $Locations -and $null -ne $Door) {
        $i = 0
        foreach ($r in @($Locations.rules)) {
            $i++
            if ($null -eq $r) { continue }
            $src = [string]$r.source
            $val = ''
            if ($src -ceq 'name') { $val = [string]$Door.name }
            elseif ($src -ceq 'id') { $val = [string]$Door.id }
            else { $val = [string](Get-JsonProp $extra $src) }
            if (-not $val -or -not [string]$r.pattern) { continue }
            $re = $null
            try { $re = New-Object System.Text.RegularExpressions.Regex([string]$r.pattern) } catch { continue }
            $m = $re.Match($val)
            if (-not $m.Success) { continue }
            foreach ($gn in $re.GetGroupNames()) {
                if ($gn -match '^\d+$') { continue }
                $g = $m.Groups[$gn]
                if ($g.Success -and $g.Value) { $fields[$gn] = $g.Value }
            }
            $ruleNo = $i
            break
        }
        $keys = @([string]$Door.id, [string]$Door.name) + $extraValues
        $map = $Locations.map
        if ($null -ne $map) {
            foreach ($k in $keys) {
                if (-not $k) { continue }
                $entry = Get-JsonProp $map $k
                if ($null -eq $entry) { continue }
                $props = @()
                if ($entry -is [System.Collections.IDictionary]) { foreach ($ek in $entry.Keys) { $props += , @([string]$ek, [string]$entry[$ek]) } }
                else { foreach ($ep in $entry.PSObject.Properties) { $props += , @([string]$ep.Name, [string]$ep.Value) } }
                foreach ($pv in $props) { if ($pv[1]) { $fields[$pv[0]] = $pv[1] } }
                break
            }
        }
    }
    $path = @()
    foreach ($lv in $levels) {
        if ($fields.Contains($lv) -and [string]$fields[$lv]) { $path += [string]$fields[$lv] } else { break }
    }
    $text = '(unplaced)'
    if ($path.Count -gt 0) { $text = ($path -join '/') }
    return [pscustomobject]@{ Fields = $fields; Path = @($path); Placed = ($path.Count -gt 0); Text = $text; Rule = $ruleNo }
}

function Test-DoorInGroup {
    # A door is in the group when it matches EVERY level listed in group.match (OR within a level's values) OR its id
    # is in group.doorIds. A group with no usable level and no id matches nothing. $Location = the Get-DoorLocation result.
    param($Door, $Location, $Group)
    if ($null -eq $Group) { return $false }
    $id = [string]$Door.id
    foreach ($x in @($Group.doorIds)) { if ($null -ne $x -and [string]$x -ceq $id) { return $true } }
    $m = Get-JsonProp $Group 'match'
    if ($null -eq $m) { return $false }
    $used = 0
    $all = $true
    $props = @()
    if ($m -is [System.Collections.IDictionary]) { foreach ($k in $m.Keys) { $props += , @([string]$k, $m[$k]) } }
    else { foreach ($p in $m.PSObject.Properties) { $props += , @([string]$p.Name, $p.Value) } }
    foreach ($pv in $props) {
        $vals = @(@($pv[1]) | Where-Object { $null -ne $_ -and [string]$_ } | ForEach-Object { [string]$_ })
        if ($vals.Count -eq 0) { continue }
        $used++
        $have = ''
        if ($Location.Fields.Contains($pv[0])) { $have = [string]$Location.Fields[$pv[0]] }
        if ($vals -cnotcontains $have) { $all = $false }
    }
    return ($used -gt 0 -and $all)
}

function ConvertTo-CsvCell {
    # One CSV cell: quoted when needed. A cell that starts with = + - @ TAB or CR, also after leading spaces, gets a '
    # in front, so a spreadsheet does not run it as a formula (spreadsheets skip the leading whitespace).
    param($Value)
    $t = [string]$Value
    if ($t -match '^[\s]*[=+\-@\t\r]') { $t = "'" + $t }
    if ($t -match '[",\r\n]') { $t = '"' + $t.Replace('"', '""') + '"' }
    return $t
}

function Write-ArmingReport {
    # CSV next to the audit file: doorkeeper-arming-<stamp>.csv. Returns the file name (without folder).
    param([string]$Label, [string]$Action, $Rows)
    $dir = Split-Path -Parent $script:AuditPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $now = [DateTime]::UtcNow
    $base = 'doorkeeper-arming-' + $now.ToString('yyyyMMdd-HHmmss')
    $name = $base + '.csv'
    $n = 1
    while (Test-Path -LiteralPath (Join-Path $dir $name)) { $n++; $name = $base + '-' + $n + '.csv' }
    $ts = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("time,action,group_or_selection,door_id,door_name,location,ok,reply_or_fault,state_after`r`n")
    foreach ($row in @($Rows)) {
        $loc = Get-DoorLocation -Door $row.Door -Locations $script:Config.locations
        $why = [string]$row.Reply
        if (-not $row.Ok) { $why = [string]$row.Fault }
        $okText = 'false'
        if ($row.Ok) { $okText = 'true' }
        $cells = @($ts, $Action, $Label, $row.Id, $row.Name, $loc.Text, $okText, $why, [string]$row.State)
        [void]$sb.Append((($cells | ForEach-Object { ConvertTo-CsvCell $_ }) -join ',') + "`r`n")
    }
    [System.IO.File]::WriteAllText((Join-Path $dir $name), $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $name
}

# ============================================================================
# License (Get-LicenseCanonicalText and Test-LicenseSignature are a VERBATIM copy of tools\New-License.ps1)
# ============================================================================

function Get-LicenseCanonicalText {
    param($License)
    $hosts = @($License.aeosHosts | ForEach-Object { ([string]$_).ToLowerInvariant() }) -join ','
    $lines = @(
        ('product=' + $License.product),
        ('licenseId=' + $License.licenseId),
        ('type=' + $License.type),
        ('customer=' + $License.customer),
        ('site=' + $License.site),
        ('aeosHosts=' + $hosts),
        ('maxDoors=' + [int]$License.maxDoors),
        ('issued=' + $License.issued),
        ('expires=' + $License.expires)
    )
    return ($lines -join "`n")
}

function Test-LicenseSignature {
    param($License, [string]$PublicKeyXml)
    try {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($PublicKeyXml)
        $data = (New-Object System.Text.UTF8Encoding($false)).GetBytes((Get-LicenseCanonicalText $License))
        $sig = [Convert]::FromBase64String([string]$License.signature)
        return [bool]$rsa.VerifyData($data, 'SHA256', $sig)
    } catch { return $false }
}

function New-LicenseResult {
    param([string]$State, [string]$Reason, $DaysLeft, $Details, [string]$HostText)
    return @{
        state = $State; reason = $Reason; daysLeft = $DaysLeft; details = $Details; aeosHost = $HostText
        actionsAllowed = (@('trial', 'licensed') -contains $State)
    }
}

function Get-LicenseStatus {
    # Decides what the console may do. Pure apart from trial.json in $DataDir, which is read when there is no
    # license text and created (first-start date) when it is missing. States: trial | licensed | expired | invalid.
    # ('none' is part of the API contract but never produced: with no license file the trial starts at once.)
    # $LicenseText is the text of license.json, or $null when there is no license file.
    # Host checks use the host of $AeosUrl and $SocketHost (each only when set). $DoorCount 0 = list not loaded yet.
    param(
        [string]$PublicKeyXml,
        [datetime]$Today,
        [string]$DataDir,
        [string]$ProductId,
        [AllowNull()]$LicenseText = $null,
        [string]$AeosUrl = '',
        [string]$SocketHost = '',
        [int]$DoorCount = 0,
        [int]$TrialDays = 30
    )
    $Today = $Today.Date
    $aeosHost = ''
    if ($AeosUrl) { try { $aeosHost = ([System.Uri]$AeosUrl).Host } catch { $aeosHost = '' } }
    $sockHost = ([string]$SocketHost).Trim()
    $toSend = New-Object System.Collections.Generic.List[string]
    foreach ($hh in @($aeosHost, $sockHost)) {
        if ($hh -and -not ($toSend | Where-Object { $_ -ieq $hh })) { $toSend.Add($hh) }
    }
    $hostText = ($toSend -join ', ')

    if ($null -eq $LicenseText) {
        $trialFile = Join-Path $DataDir 'trial.json'
        $first = $null
        if (Test-Path -LiteralPath $trialFile) {
            try {
                $t = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($trialFile))
                $d = [datetime]::MinValue
                if ([datetime]::TryParseExact([string]$t.firstStart, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { $first = $d }
            } catch { $first = $null }
        }
        if ($null -eq $first) {
            $first = $Today
            try {
                if (-not (Test-Path -LiteralPath $DataDir)) { [void](New-Item -ItemType Directory -Path $DataDir -Force) }
                $json = ConvertTo-Json -InputObject ([ordered]@{ firstStart = $first.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) })
                [System.IO.File]::WriteAllText($trialFile, $json, (New-Object System.Text.UTF8Encoding($false)))
            } catch { }
        }
        $left = $TrialDays - [int]($Today - $first).TotalDays
        if ($left -gt $TrialDays) { $left = $TrialDays }
        if ($left -gt 0) {
            return (New-LicenseResult 'trial' ('Trial version: ' + $left + ' day(s) left.') $left $null $hostText)
        }
        $endText = $first.AddDays($TrialDays).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        return (New-LicenseResult 'expired' ('The ' + $TrialDays + '-day trial ended on ' + $endText + '. Ask your supplier for a license.') 0 $null $hostText)
    }

    $lic = $null
    try { $lic = ConvertFrom-Json -InputObject ([string]$LicenseText) } catch { $lic = $null }
    if ($null -eq $lic -or $lic -isnot [System.Management.Automation.PSCustomObject]) {
        return (New-LicenseResult 'invalid' 'The license file is not valid JSON.' $null $null $hostText)
    }
    $licHosts = @(@($lic.aeosHosts) | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $details = @{
        licenseId = [string]$lic.licenseId; type = [string]$lic.type; customer = [string]$lic.customer; site = [string]$lic.site
        aeosHosts = $licHosts; maxDoors = [int]$lic.maxDoors; issued = [string]$lic.issued; expires = [string]$lic.expires
    }
    if (-not (Test-LicenseSignature -License $lic -PublicKeyXml $PublicKeyXml)) {
        return (New-LicenseResult 'invalid' 'The license signature is not valid: the file was changed or it was not issued by your supplier.' $null $details $hostText)
    }
    if ([string]$lic.product -cne $ProductId) {
        return (New-LicenseResult 'invalid' ('The license is for another product (' + [string]$lic.product + ').') $null $details $hostText)
    }
    $daysLeft = $null
    if ([string]$lic.expires) {
        $exp = [datetime]::MinValue
        if (-not [datetime]::TryParseExact([string]$lic.expires, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$exp)) {
            return (New-LicenseResult 'invalid' 'The expiry date in the license is not a date (yyyy-MM-dd).' $null $details $hostText)
        }
        if ($Today -gt $exp) {
            return (New-LicenseResult 'expired' ('The license expired on ' + [string]$lic.expires + '. Ask your supplier for a new license.') 0 $details $hostText)
        }
        $daysLeft = [int]($exp - $Today).TotalDays
    }
    foreach ($hh in $toSend) {
        if ($licHosts -notcontains $hh.ToLowerInvariant()) {
            return (New-LicenseResult 'invalid' ('The AEOS host "' + $hh + '" is not covered by this license (licensed for: ' + ($licHosts -join ', ') + ').') $null $details $hostText)
        }
    }
    $max = [int]$lic.maxDoors
    if ($max -gt 0 -and $DoorCount -gt $max) {
        return (New-LicenseResult 'invalid' ('The AEOS door list has ' + $DoorCount + ' doors; this license allows ' + $max + '.') $null $details $hostText)
    }
    return (New-LicenseResult 'licensed' 'Licensed.' $daysLeft $details $hostText)
}

function Get-CurrentLicense {
    # License status of this run: the license file (if any), the config and the last door list.
    $text = $null
    if (Test-Path -LiteralPath $script:LicensePath) {
        try { $text = [System.IO.File]::ReadAllText($script:LicensePath) } catch { $text = '' }
    }
    return (Get-LicenseStatus -PublicKeyXml $script:LicensePublicKeyXml -Today ((Get-Date).Date) -DataDir $script:DataDir -ProductId $script:LicenseProductId `
            -LicenseText $text -AeosUrl ([string]$script:Config.aeosUrl) -SocketHost ([string]$script:Config.socket.host) -DoorCount ([int]$script:LastDoorCount) -TrialDays $script:TrialDays)
}

function Assert-Licensed {
    # 402 for door actions, batch, lockdown and both raw calls when there is no valid license or trial.
    $s = Get-CurrentLicense
    if (-not $s.actionsAllowed) {
        throw (New-ApiException 402 'license_required' ($s.reason + ' Door actions are off until a valid license is imported (Setup tab, License).'))
    }
}

function Save-LicenseFile {
    param([string]$Text, [string]$Path)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $tmp = $Path + '.tmp'
    [System.IO.File]::WriteAllText($tmp, $Text, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) }
    else { [System.IO.File]::Move($tmp, $Path) }
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
    [void]$sb.AppendLine('DoorKeeper version: ' + $script:Version)
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
    Write-DebugLog $rid '==================== DoorKeeper start ===================='
    Write-DebugLog $rid ((Get-EnvironmentText).TrimEnd())
    Write-DebugLog $rid ('Listener URL: ' + $Url)
    $lic = Get-CurrentLicense
    Write-DebugLog $rid ('License: state=' + $lic.state + ' file=' + $script:LicensePath + ' - ' + $lic.reason)
    Write-DebugLog $rid ('Config (no secrets are stored in the config):' + "`r`n" + (ConvertTo-Json -InputObject $script:Config -Depth 10))
}

function Initialize-Paths {
    $script:AuditPath = Resolve-DataPath -Value ([string]$script:Config.auditFile) -BaseDir $script:ScriptDir -DefaultName 'doorkeeper-audit.jsonl'
    $script:DebugLogPath = Resolve-DataPath -Value ([string]$script:Config.debugLogFile) -BaseDir $script:ScriptDir -DefaultName 'doorkeeper-debug.log'
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
    param([string]$Action, [string]$DoorId, [string]$DoorName, [int]$HttpStatus, [bool]$Ok, [string]$Fault, [string]$Batch = '')
    $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $win = [Environment]::UserDomainName + '\' + [Environment]::UserName
    $aeos = ''
    if ($null -ne $script:Cred) { $aeos = $script:Cred.UserName }
    $prev = $script:LastAuditHash
    $hash = Get-AuditHash -PrevHash $prev -Ts $ts -WindowsUser $win -AeosUser $aeos -Action $Action -DoorId $DoorId -DoorName $DoorName -HttpStatus $HttpStatus -Ok $Ok -Batch $Batch
    $rec = [ordered]@{
        ts = $ts; windowsUser = $win; aeosUser = $aeos; action = $Action; doorId = $DoorId; doorName = $DoorName
        httpStatus = $HttpStatus; ok = $Ok; fault = $Fault; prevHash = $prev; hash = $hash
    }
    if ($Batch) { $rec['batch'] = $Batch }
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
    $req.UserAgent = 'DoorKeeper/' + $script:Version
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

# ============================================================================
# AEOS socket (TCP, optional TLS) - one session per call
# ============================================================================

function Write-SocketTrace {
    param([string]$Rid, $Session, [string]$Direction, [string]$Text)
    $line = $Direction + ' ' + (ConvertTo-VisibleControl $Text)
    [void]$Session.Transcript.Add($line)
    Write-DebugLog $Rid ('>>> SOCKET ' + $line)
}

function Send-SocketLine {
    # Sends Text plus the terminator. Shown is what goes to the log (the password is already masked there).
    param([string]$Rid, $Session, [string]$Text, [string]$Shown)
    $b = [System.Text.Encoding]::UTF8.GetBytes($Text + $Session.Term)
    $Session.Stream.Write($b, 0, $b.Length)
    $Session.Stream.Flush()
    Write-SocketTrace -Rid $Rid -Session $Session -Direction 'SEND' -Text ($Shown + $Session.Term)
}

function Read-SocketLine {
    # One non-empty received line, or $null on timeout / closed connection (Session.Closed and CloseNote tell which).
    # A read stays pending between calls (BeginRead + wait handle: SslStream has no DataAvailable).
    param($Session, [int]$TimeoutMs)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        while ($Session.Queue.Count -gt 0) {
            $l = [string]$Session.Queue.Dequeue()
            if ($l -ne '') { return $l }
        }
        if ($Session.Closed) { return $null }
        $remain = $TimeoutMs - $sw.ElapsedMilliseconds
        if ($remain -le 0) { return $null }
        if ($null -eq $Session.Pending) { $Session.Pending = $Session.Stream.BeginRead($Session.Buf, 0, $Session.Buf.Length, $null, $null) }
        if (-not $Session.Pending.AsyncWaitHandle.WaitOne([int]$remain)) { return $null }
        $n = 0
        try { $n = $Session.Stream.EndRead($Session.Pending) }
        catch {
            $Session.Pending = $null
            $Session.Closed = $true
            $Session.CloseNote = 'read failed: ' + $_.Exception.Message
            return $null
        }
        $Session.Pending = $null
        if ($n -le 0) { $Session.Closed = $true; $Session.CloseNote = 'AEOS closed the connection'; return $null }
        $Session.Text = $Session.Text + [System.Text.Encoding]::UTF8.GetString($Session.Buf, 0, $n)
        $sp = Split-SocketBuffer $Session.Text
        $Session.Text = $sp.Rest
        foreach ($l in $sp.Lines) { $Session.Queue.Enqueue($l) }
    }
}

function Get-SocketReply {
    # Waits for one reply line, logs it. Returns $null and sets Fault text when nothing came.
    param([string]$Rid, $Session, [string]$Step, [int]$TimeoutSec)
    $line = Read-SocketLine -Session $Session -TimeoutMs ($TimeoutSec * 1000)
    if ($null -ne $line) { Write-SocketTrace -Rid $Rid -Session $Session -Direction 'RECV' -Text $line; return $line }
    if ($Session.Closed) { $Session.Fault = $Session.CloseNote + ' before it answered ' + $Step + '.' }
    else { $Session.Fault = 'No reply to ' + $Step + ' within ' + $TimeoutSec + ' s.' }
    Write-DebugLog $Rid ('!!! SOCKET ' + $Session.Fault) 'ERROR'
    return $null
}

function Invoke-SocketCommandList {
    # Sends each command (hashtable: Text, Shown, Pattern, Key) and reads one reply line for each. Returns one
    # result per command: Key, Sent, Ok, Reply, Fault. A reply that does not match the pattern fails that command
    # only. No reply (timeout, closed connection) ends the list: the rest are "Not sent" with the same reason,
    # because a late reply could be taken for the answer to the next command.
    param([string]$Rid, $Session, [object[]]$Commands, [int]$ReplySec)
    $results = New-Object System.Collections.Generic.List[object]
    $stop = $null
    $n = @($Commands).Count
    $i = 0
    foreach ($c in @($Commands)) {
        $i++
        $r = [pscustomobject]@{ Key = $c.Key; Sent = $false; Ok = $false; Reply = ''; Fault = $null }
        if ($null -ne $stop) { $r.Fault = 'Not sent: ' + $stop; $results.Add($r); continue }
        $shown = [string]$c.Shown
        if (-not $shown) { $shown = [string]$c.Text }
        Send-SocketLine -Rid $Rid -Session $Session -Text ([string]$c.Text) -Shown $shown
        $r.Sent = $true
        $step = 'the command'
        if ($n -gt 1) { $step = 'command ' + $i + ' of ' + $n }
        $reply = Get-SocketReply -Rid $Rid -Session $Session -Step $step -TimeoutSec $ReplySec
        if ($null -eq $reply) { $stop = $Session.Fault; $r.Fault = $Session.Fault }
        else {
            $r.Reply = $reply
            if ([string]$c.Pattern -and -not [regex]::IsMatch($reply, [string]$c.Pattern)) { $r.Fault = 'The reply did not match the success pattern: ' + $reply }
            else { $r.Ok = $true }
        }
        $results.Add($r)
    }
    return @($results.ToArray())
}

function Invoke-SocketSession {
    # Connect, TLS when configured, greeting, login, init commands, then the commands (-Commands: hashtables with
    # Text, Shown, Pattern, Key; or one -CommandText with -SuccessPattern). Returns ok (all commands ok), reply
    # (first command), fault, transcript and results (one per command, see Invoke-SocketCommandList).
    # Connection / TLS failures throw an API exception; protocol failures come back with ok=false.
    param([string]$Rid, [string]$What, [string]$LoginText, [string]$LoginShown, [string]$CommandText, [string]$SuccessPattern, [object[]]$Commands = $null)
    if ($null -eq $Commands) { $Commands = @(@{ Text = $CommandText; Shown = $CommandText; Pattern = $SuccessPattern; Key = '' }) }
    $cfg = $script:Config
    $sk = $cfg.socket
    $hostName = Resolve-SocketHost -SocketHost ([string]$sk.host) -AeosUrl ([string]$cfg.aeosUrl)
    $port = [int]$sk.port
    if (-not $hostName -or $port -lt 1 -or $port -gt 65535) {
        throw (New-ApiException 400 'not_configured' 'The socket host and port are not set. Open the Setup tab (Socket interface).')
    }
    $useTls = ($sk.tls -ne $false)
    $replySec = [int]$sk.replyTimeoutSec
    $tmo = ([int]$cfg.timeoutSec) * 1000
    $session = @{
        Stream = $null; Buf = (New-Object byte[] 8192); Pending = $null; Text = ''; Queue = (New-Object System.Collections.Queue)
        Closed = $false; CloseNote = ''; Fault = $null; Term = (Get-SocketTerminatorText ([string]$sk.terminator))
        Transcript = (New-Object System.Collections.Generic.List[string])
    }
    $out = @{ ok = $false; reply = ''; fault = $null; transcript = @(); results = @() }
    $results = @()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-DebugLog $Rid ('>>> SOCKET [' + $What + '] connect ' + $hostName + ':' + $port + ' tls=' + $useTls + ' tlsSkipValidation=' + ($sk.tlsSkipValidation -eq $true) +
        ' terminator=' + $sk.terminator + ' (connect timeout ' + $cfg.timeoutSec + ' s, reply timeout ' + $replySec + ' s)')
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        try {
            $ar = $tcp.BeginConnect($hostName, $port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne($tmo)) { throw ('no connection within ' + $cfg.timeoutSec + ' s') }
            $tcp.EndConnect($ar)
        }
        catch {
            Write-DebugLog $Rid ('!!! SOCKET connect failed' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
            throw (New-ApiException 502 'socket_unreachable' ('Cannot connect to the AEOS socket ' + $hostName + ':' + $port + ': ' + $_.Exception.Message))
        }
        Write-DebugLog $Rid ('SOCKET connected to ' + $tcp.Client.RemoteEndPoint)
        if ($useTls) {
            Initialize-TlsCallbackType
            $cb = New-Object AeosTlsCallback
            $cb.Skip = ($sk.tlsSkipValidation -eq $true)
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb.Callback)
            try { $ssl.AuthenticateAsClient($hostName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false) }
            catch {
                foreach ($l in $cb.Lines) { Write-DebugLog $Rid $l }
                Write-DebugLog $Rid ('!!! SOCKET TLS handshake failed' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
                $m = $_.Exception.Message
                $ie = $_.Exception.InnerException
                while ($null -ne $ie) { $m = $m + ' -> ' + $ie.Message; $ie = $ie.InnerException }
                $hint = ''
                if (-not $cb.Skip) { $hint = ' (self-signed AEOS certificate? tick "Skip TLS certificate validation" in the Socket interface settings)' }
                throw (New-ApiException 502 'socket_tls' ('TLS handshake with the AEOS socket failed: ' + $m + $hint))
            }
            foreach ($l in $cb.Lines) { Write-DebugLog $Rid $l }
            Write-DebugLog $Rid ('SOCKET TLS ' + $ssl.SslProtocol + ', cipher ' + $ssl.CipherAlgorithm + '/' + $ssl.CipherStrength)
            $session.Stream = $ssl
        }
        else { $session.Stream = $tcp.GetStream() }

        # greeting: wait up to greetingWaitMs for the first line, then take what follows while it keeps coming
        $gw = [int]$sk.greetingWaitMs
        if ($gw -gt 0) {
            $g = Read-SocketLine -Session $session -TimeoutMs $gw
            while ($null -ne $g) {
                Write-SocketTrace -Rid $Rid -Session $session -Direction 'RECV' -Text $g
                $g = Read-SocketLine -Session $session -TimeoutMs 200
            }
            if ($session.Closed) { $session.Fault = $session.CloseNote + ' during the greeting.' }
        }
        $go = (-not $session.Closed)

        if ($go -and $LoginText) {
            Send-SocketLine -Rid $Rid -Session $session -Text $LoginText -Shown $LoginShown
            $lr = Get-SocketReply -Rid $Rid -Session $session -Step 'the login' -TimeoutSec $replySec
            if ($null -eq $lr) { $go = $false; $session.Fault = 'Login failed: ' + $session.Fault }
            else {
                $lp = [string]$sk.loginSuccessPattern
                if ($lp -and -not [regex]::IsMatch($lr, $lp)) { $go = $false; $session.Fault = 'login rejected: ' + $lr }
            }
        }
        if ($go) {
            foreach ($ic in @($sk.initCommands)) {
                if (-not [string]$ic) { continue }
                Send-SocketLine -Rid $Rid -Session $session -Text ([string]$ic) -Shown ([string]$ic)
                $ir = Get-SocketReply -Rid $Rid -Session $session -Step ('the init command "' + $ic + '"') -TimeoutSec $replySec
                if ($null -eq $ir) { $go = $false; break }
            }
        }
        if ($go) { $results = @(Invoke-SocketCommandList -Rid $Rid -Session $session -Commands $Commands -ReplySec $replySec) }
        else {
            foreach ($c in @($Commands)) {
                $results += [pscustomobject]@{ Key = $c.Key; Sent = $false; Ok = $false; Reply = ''; Fault = ('Not sent: ' + $session.Fault) }
            }
        }
    }
    finally {
        $sw.Stop()
        try { $tcp.Close() } catch { }
        Write-DebugLog $Rid ('<<< SOCKET [' + $What + '] closed after ' + $sw.ElapsedMilliseconds + ' ms')
    }
    $out.results = @($results)
    $bad = @($results | Where-Object { -not $_.Ok })
    $out.ok = ($results.Count -gt 0 -and $bad.Count -eq 0)
    if ($results.Count -gt 0) { $out.reply = [string]$results[0].Reply }
    $out.fault = $session.Fault
    if (-not $out.fault -and $bad.Count -gt 0) { $out.fault = [string]$bad[0].Fault }
    $out.transcript = @($session.Transcript.ToArray())
    Write-DebugLog $Rid ('Call result [' + $What + ']: socket ok=' + $out.ok + $(if ($out.fault) { ' fault="' + $out.fault + '"' } else { '' }))
    return $out
}

function Get-SocketLoginText {
    # Expands the login template. Returns Text, Shown (password masked for the log) and Error.
    param([string]$Rid)
    $tpl = [string]$script:Config.socket.loginTemplate
    $res = [pscustomobject]@{ Text = ''; Shown = ''; Error = $null }
    if (-not $tpl) { return $res }
    $user = ''
    $pw = ''
    if ($tpl -match '\{\{(user|password)\}\}') {
        if ($null -eq $script:Cred) { throw (New-ApiException 401 'not_logged_in' 'Log in with the AEOS user first.') }
        $user = $script:Cred.UserName
        $pw = $script:Cred.GetNetworkCredential().Password
    }
    $real = Expand-SocketTemplate -Template $tpl -User $user -Password $pw -Login
    if ($real.Error) { $res.Error = $real.Error; return $res }
    $shown = Expand-SocketTemplate -Template $tpl -User $user -Password '****' -Login
    $res.Text = $real.Text
    $res.Shown = $shown.Text
    return $res
}

function Get-DoorStateChecks {
    # The configured state checks that have a command, in order.
    $list = @()
    $ds = $script:Config.doorState
    if ($null -ne $ds) { foreach ($c in @($ds.checks)) { if ($null -ne $c -and [string]$c.command) { $list += $c } } }
    return @($list)
}

function Get-MaxDoorsPerRefresh {
    $n = 500
    if ($null -ne $script:Config.doorState) { [void][int]::TryParse([string]$script:Config.doorState.maxDoorsPerRefresh, [ref]$n) }
    if ($n -lt 1) { $n = 500 }
    return $n
}

function Get-DoorStatePlan {
    # Expands every state check for every door. A door with a refused value gets Error and no commands.
    # Returns one entry per door, in order: Door, Commands (the texts), Error.
    param($Doors, $Checks)
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Doors)) {
        $e = [pscustomobject]@{ Door = $d; Commands = @(); Error = $null }
        $texts = @()
        foreach ($c in @($Checks)) {
            $x = Expand-SocketTemplate -Template ([string]$c.command) -Id ([string]$d.id) -Name ([string]$d.name) -Extra $d.extra
            if ($x.Error) { $e.Error = $x.Error; $texts = @(); break }
            $texts += $x.Text
        }
        $e.Commands = @($texts)
        $plan.Add($e)
    }
    return @($plan.ToArray())
}

function Get-DoorStateCommands {
    # Session commands for a plan: the check commands of every door without an error, door by door.
    param($Plan)
    $cmds = @()
    $di = 0
    foreach ($p in @($Plan)) {
        $ci = 0
        foreach ($t in @($p.Commands)) {
            $cmds += @{ Text = [string]$t; Shown = [string]$t; Pattern = ''; Key = ('state:' + $di + ':' + $ci) }
            $ci++
        }
        $di++
    }
    return @($cmds)
}

function Resolve-DoorState {
    # Checks[i] pairs with Results[i] (Ok, Reply, Fault). The state is the label of the first check whose reply
    # matches its pattern; none matches = the otherwise label; a missing or failed reply = "?" with the reason.
    param($Checks, $Results, [string]$OtherwiseLabel)
    $c = @($Checks)
    $r = @($Results)
    $replies = @()
    for ($i = 0; $i -lt $c.Count; $i++) {
        $res = $null
        if ($i -lt $r.Count) { $res = $r[$i] }
        if ($null -eq $res -or -not $res.Ok) {
            $why = 'No reply.'
            if ($null -ne $res -and $res.Fault) { $why = [string]$res.Fault }
            return @{ state = '?'; detail = $why }
        }
        if ([regex]::IsMatch([string]$res.Reply, [string]$c[$i].matchPattern)) { return @{ state = [string]$c[$i].label; detail = [string]$res.Reply } }
        $replies += [string]$res.Reply
    }
    return @{ state = $OtherwiseLabel; detail = ($replies -join ' | ') }
}

function Get-DoorStatesFromResults {
    # Plan + the session results of its commands (same order) -> one @{id; state; detail} per door.
    param($Plan, $Checks, $Results, [string]$OtherwiseLabel)
    $out = @()
    $r = @($Results)
    $k = 0
    $n = @($Checks).Count
    foreach ($p in @($Plan)) {
        $id = [string]$p.Door.id
        if ($p.Error) { $out += @{ id = $id; state = '?'; detail = [string]$p.Error }; continue }
        $mine = @()
        for ($i = 0; $i -lt $n; $i++) { if (($k + $i) -lt $r.Count) { $mine += $r[$k + $i] } }
        $k += $n
        $st = Resolve-DoorState -Checks $Checks -Results $mine -OtherwiseLabel $OtherwiseLabel
        $out += @{ id = $id; state = $st.state; detail = $st.detail }
    }
    return @($out)
}

function Get-DoorStates {
    # One socket session for all listed doors: login + init once, then the state checks of every door.
    param([string]$Rid, $Doors)
    $checks = @(Get-DoorStateChecks)
    if ($checks.Count -eq 0) { throw (New-ApiException 400 'not_configured' 'No door state checks are set. Open the Setup tab (Door state).') }
    $list = @($Doors | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { throw (New-ApiException 400 'bad_request' 'No doors to check.') }
    # More doors than "Doors per socket session" are read in several sessions, one after the other.
    $max = Get-MaxDoorsPerRefresh
    $states = @()
    $login = $null
    for ($off = 0; $off -lt $list.Count; $off += $max) {
        $part = @($list[$off..([Math]::Min($off + $max, $list.Count) - 1)])
        $plan = @(Get-DoorStatePlan -Doors $part -Checks $checks)
        $cmds = @(Get-DoorStateCommands -Plan $plan)
        $results = @()
        if ($cmds.Count -gt 0) {
            if ($null -eq $login) {
                $login = Get-SocketLoginText -Rid $Rid
                if ($login.Error) {
                    Write-DebugLog $Rid ('Refused before sending: ' + $login.Error) 'ERROR'
                    throw (New-ApiException 400 'bad_value' $login.Error)
                }
            }
            if ($list.Count -gt $max) { Write-DebugLog $Rid ('State session for doors ' + ($off + 1) + '-' + ($off + $part.Count) + ' of ' + $list.Count) }
            $sess = Invoke-SocketSession -Rid $Rid -What 'state' -LoginText $login.Text -LoginShown $login.Shown -Commands $cmds
            $results = @($sess.results)
        }
        $states += @(Get-DoorStatesFromResults -Plan $plan -Checks $checks -Results $results -OtherwiseLabel ([string]$script:Config.doorState.otherwiseLabel))
    }
    return @{ states = @($states) }
}

function Invoke-SocketDoorAction {
    # The action command, then (when state checks are configured) the checks for this door in the same session.
    param([string]$Rid, [string]$Action, [string]$Id, [string]$Name, $Extra)
    $a = $script:Config.actions.$Action
    $cmd = Expand-SocketTemplate -Template ([string]$a.command) -Id $Id -Name $Name -Extra $Extra
    if ($cmd.Error) {
        Write-DebugLog $Rid ('Refused before sending: ' + $cmd.Error) 'ERROR'
        throw (New-ApiException 400 'bad_value' $cmd.Error)
    }
    $login = Get-SocketLoginText -Rid $Rid
    if ($login.Error) {
        Write-DebugLog $Rid ('Refused before sending: ' + $login.Error) 'ERROR'
        throw (New-ApiException 400 'bad_value' $login.Error)
    }
    $commands = @(@{ Text = $cmd.Text; Shown = $cmd.Text; Pattern = [string]$a.successPattern; Key = 'action' })
    $checks = @(Get-DoorStateChecks)
    $plan = @()
    if ($checks.Count -gt 0) {
        $plan = @(Get-DoorStatePlan -Doors @([pscustomobject]@{ id = $Id; name = $Name; extra = $Extra }) -Checks $checks)
        $commands += @(Get-DoorStateCommands -Plan $plan)
    }
    $sess = Invoke-SocketSession -Rid $Rid -What $Action -LoginText $login.Text -LoginShown $login.Shown -Commands $commands
    $r0 = $sess.results[0]
    $res = @{ ok = [bool]$r0.Ok; reply = [string]$r0.Reply; fault = $null; transcript = $sess.transcript; state = $null; stateDetail = '' }
    if (-not $r0.Ok) { $res.fault = $sess.fault; if (-not $res.fault) { $res.fault = [string]$r0.Fault } }
    if ($checks.Count -gt 0) {
        $st = @(Get-DoorStatesFromResults -Plan $plan -Checks $checks -Results @($sess.results | Select-Object -Skip 1) -OtherwiseLabel ([string]$script:Config.doorState.otherwiseLabel))
        $res.state = [string]$st[0].state
        $res.stateDetail = [string]$st[0].detail
    }
    return $res
}

function Invoke-SocketRaw {
    # Raw call tab: one typed command in the same session procedure. Audited like a door action.
    param([string]$Rid, [string]$Command)
    if (-not $Command -or $Command.IndexOfAny([char[]]@("`r", "`n")) -ge 0) {
        throw (New-ApiException 400 'bad_request' 'Enter exactly one socket command (no line breaks).')
    }
    $login = Get-SocketLoginText -Rid $Rid
    if ($login.Error) {
        Write-DebugLog $Rid ('Refused before sending: ' + $login.Error) 'ERROR'
        throw (New-ApiException 400 'bad_value' $login.Error)
    }
    $result = $null
    $caught = $null
    try { $result = Invoke-SocketSession -Rid $Rid -What 'raw socket' -LoginText $login.Text -LoginShown $login.Shown -CommandText $Command -SuccessPattern '' }
    catch { $caught = $_.Exception }
    $ok = $false
    $fault = $null
    if ($null -ne $result) { $ok = $result.ok; $fault = $result.fault }
    elseif ($null -ne $caught) { $fault = $caught.Message }
    Write-AuditRecord -Action 'raw-socket' -DoorId '' -DoorName $Command -HttpStatus 0 -Ok $ok -Fault $fault
    Write-DebugLog $Rid ('Audit record written: action=raw-socket ok=' + $ok)
    if ($null -ne $caught) { throw $caught }
    return @{ ok = $result.ok; fault = $result.fault; reply = $result.reply; transcript = $result.transcript }
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
    param([string]$Rid, [string]$Action, [string]$Id, [string]$Name, $Extra = $null)
    if (@('lock', 'unlock', 'access', 'normal') -notcontains $Action) { throw (New-ApiException 400 'bad_action' 'Unknown action.') }
    $a = $script:Config.actions.$Action
    $socket = ([string]$a.transport -eq 'socket')
    if ($socket) {
        if (-not $a.command) { throw (New-ApiException 400 'not_configured' ('The ' + $Action + ' action has no socket command on the Setup tab.')) }
    }
    else {
        if (-not $a.operation) { throw (New-ApiException 400 'not_configured' ('The ' + $Action + ' action is not mapped on the Setup tab.')) }
        Assert-CanCall
    }
    $result = $null
    $caught = $null
    try {
        if ($socket) { $result = Invoke-SocketDoorAction -Rid $Rid -Action $Action -Id $Id -Name $Name -Extra $Extra }
        else { $result = Invoke-SoapCall -Rid $Rid -What $Action -SoapAction ([string]$a.soapAction) -BodyTemplate ([string]$a.body) -Id $Id -Name $Name }
    }
    catch { $caught = $_.Exception }
    $status = 0
    $ok = $false
    $fault = $null
    if ($null -ne $result) {
        $ok = $result.ok
        $fault = $result.fault
        if (-not $socket) { $status = $result.httpStatus }
    }
    elseif ($null -ne $caught) { $fault = $caught.Message }
    Write-AuditRecord -Action $Action -DoorId $Id -DoorName $Name -HttpStatus $status -Ok $ok -Fault $fault
    Write-DebugLog $Rid ('Audit record written: action=' + $Action + ' doorId=' + $Id + ' ok=' + $ok)
    if ($null -ne $caught) { throw $caught }
    if ($socket) {
        $o = @{ ok = $result.ok; transport = 'socket'; httpStatus = 0; fault = $result.fault; reply = $result.reply; response = $result.reply }
        if ($null -ne $result.state) { $o.state = $result.state; $o.stateDetail = $result.stateDetail }
        return $o
    }
    return @{ ok = $result.ok; httpStatus = $result.httpStatus; fault = $result.fault; response = $result.response }
}

function Invoke-DoorBatch {
    # One action on many doors. Socket transport: ONE session (login + init once, the action command of every door,
    # then the state checks of every door). SOAP transport: one call per door in turn. A door with a refused value is
    # reported and not sent; the others go on. One audit record per door, tagged batch:<request id>.
    # -Report (an object with a label) also writes the arming report CSV next to the audit file; the answer names it.
    param([string]$Rid, [string]$Action, $Doors, $Report = $null)
    if (@('lock', 'unlock', 'access', 'normal') -notcontains $Action) { throw (New-ApiException 400 'bad_action' 'Unknown action.') }
    $a = $script:Config.actions.$Action
    $socket = ([string]$a.transport -eq 'socket')
    if ($socket) {
        if (-not $a.command) { throw (New-ApiException 400 'not_configured' ('The ' + $Action + ' action has no socket command on the Setup tab.')) }
    }
    else {
        if (-not $a.operation) { throw (New-ApiException 400 'not_configured' ('The ' + $Action + ' action is not mapped on the Setup tab.')) }
        Assert-CanCall
    }
    $list = @($Doors | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { throw (New-ApiException 400 'bad_request' 'Select at least one door.') }
    $max = Get-MaxDoorsPerRefresh
    $tag = 'batch:' + $Rid
    $checks = @(Get-DoorStateChecks)
    $other = [string]$script:Config.doorState.otherwiseLabel
    $rows = @()
    foreach ($d in $list) {
        $rows += [pscustomobject]@{ Id = [string]$d.id; Name = [string]$d.name; Door = $d; Ok = $false; Refused = $false; Fault = $null; Reply = ''; Text = ''; State = $null; StateDetail = ''; HttpStatus = 0 }
    }
    $caught = $null
    $states = $null
    if ($socket) {
        $send = @()
        foreach ($row in $rows) {
            $x = Expand-SocketTemplate -Template ([string]$a.command) -Id $row.Id -Name $row.Name -Extra $row.Door.extra
            if ($x.Error) { $row.Refused = $true; $row.Fault = $x.Error; Write-DebugLog $Rid ('Refused before sending [' + $row.Name + ']: ' + $x.Error) 'ERROR' }
            else { $row.Text = $x.Text; $send += $row }
        }
        # More doors than "Doors per socket session" go in several sessions, one after the other. A failure in the
        # first session fails the batch as before; a later failure leaves the doors already done as they are and marks
        # the rest "Not sent", so the report shows exactly what happened.
        if ($checks.Count -gt 0) { $states = @() }
        $login = $null
        $stopWhy = $null
        for ($off = 0; $off -lt $send.Count; $off += $max) {
            $part = @($send[$off..([Math]::Min($off + $max, $send.Count) - 1)])
            if ($null -ne $stopWhy) {
                foreach ($row in $part) { $row.Ok = $false; $row.Fault = 'Not sent: ' + $stopWhy }
                continue
            }
            $cmds = @()
            foreach ($row in $part) { $cmds += @{ Text = $row.Text; Shown = $row.Text; Pattern = [string]$a.successPattern; Key = 'action' } }
            $plan = @()
            if ($checks.Count -gt 0) {
                $plan = @(Get-DoorStatePlan -Doors @($part | ForEach-Object { $_.Door }) -Checks $checks)
                $cmds += @(Get-DoorStateCommands -Plan $plan)
            }
            try {
                if ($null -eq $login) {
                    $login = Get-SocketLoginText -Rid $Rid
                    if ($login.Error) {
                        Write-DebugLog $Rid ('Refused before sending: ' + $login.Error) 'ERROR'
                        throw (New-ApiException 400 'bad_value' $login.Error)
                    }
                }
                if ($send.Count -gt $max) { Write-DebugLog $Rid ('Batch session for doors ' + ($off + 1) + '-' + ($off + $part.Count) + ' of ' + $send.Count) }
                $sess = Invoke-SocketSession -Rid $Rid -What ('batch ' + $Action) -LoginText $login.Text -LoginShown $login.Shown -Commands $cmds
                $rs = @($sess.results)
                for ($i = 0; $i -lt $part.Count; $i++) {
                    $part[$i].Ok = [bool]$rs[$i].Ok
                    $part[$i].Reply = [string]$rs[$i].Reply
                    if (-not $rs[$i].Ok) { $part[$i].Fault = [string]$rs[$i].Fault }
                }
                if ($plan.Count -gt 0) { $states += @(Get-DoorStatesFromResults -Plan $plan -Checks $checks -Results @($rs | Select-Object -Skip $part.Count) -OtherwiseLabel $other) }
            }
            catch {
                foreach ($row in $part) { $row.Ok = $false; $row.Fault = $_.Exception.Message }
                if ($off -eq 0) { $caught = $_.Exception; $stopWhy = $_.Exception.Message }
                else { $stopWhy = $_.Exception.Message; Write-DebugLog $Rid ('Batch stopped after ' + $off + ' door(s): ' + $stopWhy) 'ERROR' }
            }
        }
    }
    else {
        $stopWhy = $null
        foreach ($row in $rows) {
            if ($null -ne $stopWhy) { $row.Fault = 'Not sent: ' + $stopWhy; continue }
            try {
                $r = Invoke-SoapCall -Rid $Rid -What $Action -SoapAction ([string]$a.soapAction) -BodyTemplate ([string]$a.body) -Id $row.Id -Name $row.Name
                $row.Ok = [bool]$r.ok
                $row.HttpStatus = [int]$r.httpStatus
                $row.Fault = $r.fault
                if (-not $r.ok -and -not $r.fault) { $row.Fault = 'HTTP ' + $r.httpStatus }
            }
            catch { $row.Fault = $_.Exception.Message; $stopWhy = $_.Exception.Message }
        }
        if ($checks.Count -gt 0) {
            try { $states = @((Get-DoorStates -Rid $Rid -Doors @($rows | ForEach-Object { $_.Door })).states) }
            catch {
                $m = $_.Exception.Message
                $states = @($rows | ForEach-Object { @{ id = $_.Id; state = '?'; detail = $m } })
            }
        }
    }
    $okCount = 0
    foreach ($row in $rows) {
        if ($row.Ok) { $okCount++ }
        Write-AuditRecord -Action $Action -DoorId $row.Id -DoorName $row.Name -HttpStatus $row.HttpStatus -Ok $row.Ok -Fault $row.Fault -Batch $tag
    }
    Write-DebugLog $Rid ('Audit records written: ' + $rows.Count + ' x action=' + $Action + ' ' + $tag + ' ok=' + $okCount)
    if ($null -ne $caught) { throw $caught }
    # states come one per door in plan order (socket: only the doors that were sent; SOAP: all doors)
    if ($null -ne $states) {
        $withState = @($rows)
        if ($socket) { $withState = @($rows | Where-Object { -not $_.Refused }) }
        for ($i = 0; $i -lt $withState.Count -and $i -lt $states.Count; $i++) {
            $withState[$i].State = [string]$states[$i].state
            $withState[$i].StateDetail = [string]$states[$i].detail
        }
    }
    $out = @()
    foreach ($row in $rows) {
        $o = @{ id = $row.Id; name = $row.Name; ok = $row.Ok; refused = $row.Refused; fault = $row.Fault; reply = $row.Reply }
        if ($null -ne $row.State) { $o.state = $row.State; $o.stateDetail = $row.StateDetail }
        $out += $o
    }
    $tr = 'soap'
    if ($socket) { $tr = 'socket' }
    $reportFile = ''
    $reportError = ''
    if ($null -ne $Report) {
        try {
            $lab = ([string](Get-JsonProp $Report 'label')).Trim()
            if ($lab.Length -gt 200) { $lab = $lab.Substring(0, 200) }
            $reportFile = Write-ArmingReport -Label $lab -Action $Action -Rows $rows
            Write-DebugLog $Rid ('Arming report written: ' + $reportFile)
        }
        catch { $reportError = $_.Exception.Message; Write-DebugLog $Rid ('Arming report not written: ' + $reportError) 'ERROR' }
    }
    return @{ ok = ($okCount -eq $rows.Count); action = $Action; transport = $tr; batch = $Rid; count = $rows.Count; okCount = $okCount; failCount = ($rows.Count - $okCount); results = @($out); reportFile = $reportFile; reportError = $reportError }
}

function Get-PagedDoorList {
    # Runs the door list one page at a time. Fetch is a scriptblock: param([string]$Body, [int]$Page) that returns
    # @{ ok; httpStatus; fault; doors; raw }. Paging runs only when PageSize > 0 and the body holds {{start}}:
    # {{start}} = record offset (0, PageSize, 2*PageSize ...), {{pageSize}} = PageSize. Stops on a short page, a page
    # with no new id (the server ignores the offset) or MaxPages. Doors are kept by id, first wins.
    # A failed page fails the whole list (ok=false, failedPage set) - never a half list that looks complete.
    param([string]$BodyTemplate, [int]$PageSize, [scriptblock]$Fetch, [int]$MaxPages = 1000)
    if ($null -eq $BodyTemplate) { $BodyTemplate = '' }
    $paged = ($PageSize -gt 0 -and $BodyTemplate.Contains('{{start}}'))
    $all = New-Object System.Collections.ArrayList
    $seen = @{}
    $page = 0
    $raw = $null
    while ($true) {
        $page++
        $body = $BodyTemplate
        if ($paged) { $body = $body.Replace('{{start}}', [string](($page - 1) * $PageSize)).Replace('{{pageSize}}', [string]$PageSize) }
        $r = & $Fetch $body $page
        if ($page -eq 1) { $raw = $r.raw }
        if (-not $r.ok) {
            return @{ ok = $false; httpStatus = $r.httpStatus; fault = $r.fault; doors = @($all.ToArray()); raw = $r.raw; pages = $page; failedPage = $page }
        }
        $got = @($r.doors)
        $new = 0
        foreach ($d in $got) {
            $k = [string]$d.id
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true
            [void]$all.Add($d)
            $new++
        }
        if (-not $paged -or $got.Count -lt $PageSize -or $new -eq 0 -or $page -ge $MaxPages) { break }
    }
    return @{ ok = $true; httpStatus = $r.httpStatus; fault = $null; doors = @($all.ToArray()); raw = $raw; pages = $page; failedPage = 0 }
}

function Get-DoorsFromServer {
    param([string]$Rid)
    $a = $script:Config.actions.listDoors
    if (-not $a.operation) { throw (New-ApiException 400 'not_configured' 'The list doors action is not mapped on the Setup tab.') }
    if (-not $a.itemElement -or -not $a.idField) { throw (New-ApiException 400 'not_configured' 'Set the door element and the id field on the Setup tab.') }
    $ps = 0
    [void][int]::TryParse([string]$a.pageSize, [ref]$ps)
    $fetch = {
        param([string]$Body, [int]$Page)
        $r = Invoke-SoapCall -Rid $Rid -What 'listDoors' -SoapAction ([string]$a.soapAction) -BodyTemplate $Body
        $d = @()
        if ($r.ok) {
            try { $d = @(ConvertFrom-DoorList -Text $r.rawText -ItemElement ([string]$a.itemElement) -IdField ([string]$a.idField) -NameField ([string]$a.nameField) -ExtraFields @($a.extraFields)) }
            catch {
                Write-DebugLog $Rid ('Door list parse failed (page ' + $Page + ')' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
                throw (New-ApiException 502 'parse_failed' ('The response could not be parsed (page ' + $Page + '): ' + $_.Exception.Message))
            }
            Write-DebugLog $Rid ('Door list page ' + $Page + ': ' + $d.Count + ' door(s) with element "' + $a.itemElement + '"')
        }
        return @{ ok = $r.ok; httpStatus = $r.httpStatus; fault = $r.fault; doors = @($d); raw = $r.response }
    }
    $res = Get-PagedDoorList -BodyTemplate ([string]$a.body) -PageSize $ps -Fetch $fetch
    if ($res.ok) {
        Write-DebugLog $Rid ('Door list parsed: ' + @($res.doors).Count + ' door(s) in ' + $res.pages + ' page(s)')
        $script:LastDoorCount = @($res.doors).Count
    }
    elseif ($res.failedPage -gt 1) {
        $why = $res.fault
        if (-not $why) { $why = 'HTTP ' + $res.httpStatus }
        $res.fault = 'page ' + $res.failedPage + ' failed after ' + @($res.doors).Count + ' door(s): ' + $why
    }
    return @{ ok = $res.ok; httpStatus = $res.httpStatus; fault = $res.fault; doors = @($res.doors); raw = $res.raw; pages = $res.pages }
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
    $name = 'doorkeeper-diag-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip'
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

function Read-RequestText {
    param($Request, [int]$MaxChars = 65536)
    $sr = New-Object System.IO.StreamReader($Request.InputStream, [System.Text.Encoding]::UTF8)
    $text = $sr.ReadToEnd()
    if ($text.Length -gt $MaxChars) { throw (New-ApiException 413 'too_large' 'Request body too large.') }
    return $text
}

function Invoke-Route {
    param($Ctx, [string]$Rid)
    $req = $Ctx.Request
    $method = $req.HttpMethod.ToUpperInvariant()
    $path = $req.Url.AbsolutePath
    if (-not $req.IsLocal) { return (New-ErrorResult 403 'forbidden' 'Requests are accepted from this computer only.') }
    if ($method -eq 'GET' -and $path -eq '/') {
        $html = $script:PageHtml.Replace('__TOKEN__', $script:Token).Replace('__VERSION__', $script:Version)
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
        'GET /api/v1/license' {
            return @{ Status = 200; Json = (Get-CurrentLicense) }
        }
        'PUT /api/v1/license' {
            $text = Read-RequestText $req
            if (-not $text.Trim()) { throw (New-ApiException 400 'bad_request' 'Empty request body. Send the text of license.json.') }
            $cand = Get-LicenseStatus -PublicKeyXml $script:LicensePublicKeyXml -Today ((Get-Date).Date) -DataDir $script:DataDir -ProductId $script:LicenseProductId `
                -LicenseText $text -AeosUrl ([string]$script:Config.aeosUrl) -SocketHost ([string]$script:Config.socket.host) -DoorCount ([int]$script:LastDoorCount)
            if ($cand.state -ne 'licensed') {
                Write-DebugLog $Rid ('License import refused (' + $cand.state + '): ' + $cand.reason)
                throw (New-ApiException 400 'invalid_license' ($cand.reason + ' The file was not saved.'))
            }
            Save-LicenseFile -Text $text -Path $script:LicensePath
            Write-DebugLog $Rid ('License imported and saved to ' + $script:LicensePath + ' (licenseId ' + $cand.details.licenseId + ')')
            return @{ Status = 200; Json = (Get-CurrentLicense) }
        }
        'POST /api/v1/call' {
            Assert-Licensed
            $in = Read-RequestJson $req
            if ($null -eq $in -or -not [string]$in.body) { throw (New-ApiException 400 'bad_request' 'A request body (XML) is required.') }
            $r = Invoke-SoapCall -Rid $Rid -What ('raw ' + [string]$in.operation) -SoapAction ([string]$in.soapAction) -BodyTemplate ([string]$in.body)
            return @{ Status = 200; Json = @{ httpStatus = $r.httpStatus; ok = $r.ok; fault = $r.fault; response = $r.response } }
        }
        'GET /api/v1/doors' {
            return @{ Status = 200; Json = (Get-DoorsFromServer -Rid $Rid) }
        }
        'POST /api/v1/doors/action' {
            Assert-Licensed
            $in = Read-RequestJson $req
            if ($null -eq $in) { throw (New-ApiException 400 'bad_request' 'Empty request body.') }
            return @{ Status = 200; Json = (Invoke-DoorAction -Rid $Rid -Action ([string]$in.action) -Id ([string]$in.id) -Name ([string]$in.name) -Extra $in.extra) }
        }
        'POST /api/v1/doors/state' {
            $in = Read-RequestJson $req
            if ($null -eq $in -or $null -eq $in.doors) { throw (New-ApiException 400 'bad_request' 'A list of doors is required.') }
            return @{ Status = 200; Json = (Get-DoorStates -Rid $Rid -Doors @($in.doors)) }
        }
        'POST /api/v1/doors/batch' {
            Assert-Licensed
            $in = Read-RequestJson $req
            if ($null -eq $in -or $null -eq $in.doors) { throw (New-ApiException 400 'bad_request' 'An action and a list of doors are required.') }
            return @{ Status = 200; Json = (Invoke-DoorBatch -Rid $Rid -Action ([string]$in.action) -Doors @($in.doors) -Report $in.report) }
        }
        'POST /api/v1/socket' {
            Assert-Licensed
            $in = Read-RequestJson $req
            if ($null -eq $in) { throw (New-ApiException 400 'bad_request' 'Empty request body.') }
            return @{ Status = 200; Json = (Invoke-SocketRaw -Rid $Rid -Command ([string]$in.command)) }
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
        'GET /api/v1/arming/report' {
            $f = [string]$req.QueryString['file']
            if ($f -notmatch '^doorkeeper-arming-\d{8}-\d{6}(-\d+)?\.csv$') { throw (New-ApiException 400 'bad_request' 'Bad file name.') }
            $p = Join-Path (Split-Path -Parent $script:AuditPath) $f
            if (-not (Test-Path -LiteralPath $p)) { throw (New-ApiException 404 'not_found' 'No such arming report.') }
            return @{ Status = 200; Bytes = [System.IO.File]::ReadAllBytes($p); ContentType = 'text/csv; charset=utf-8'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="' + $f + '"' } }
        }
        'POST /api/v1/diagnostics' {
            $p = New-DiagnosticsZip
            Write-DebugLog $Rid ('Diagnostics zip created: ' + $p)
            return @{ Status = 200; Json = @{ path = $p; fileName = [System.IO.Path]::GetFileName($p) } }
        }
        'GET /api/v1/diagnostics/download' {
            $f = [string]$req.QueryString['file']
            if ($f -notmatch '^doorkeeper-diag-\d{8}-\d{6}\.zip$') { throw (New-ApiException 400 'bad_request' 'Bad file name.') }
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
    # Errors returned (not thrown) by the route, e.g. the 403 token / origin checks, also name their reason in the log.
    if (-not $errNote -and $result.Status -ge 400 -and $result.Json -and $result.Json.error) {
        $errNote = ' error=' + $result.Json.error.code + ': ' + $result.Json.error.message
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
<meta name="console-version" content="__VERSION__">
<title>DoorKeeper</title>
<style>
:root{--ink:#131C30;--blue:#4B8BFF;--blue-deep:#2F6FE0;--blue-dark:#1E4FB8;--text:#1F2733;--muted:#5F6B7A;--line:#D9DDE5;--field:#C9CFDA;
--surface:#F3F5F8;--tint:#EEF3FF;--tint-line:#BFD3FF;--red:#B42318;--head-line:#3A4660;--head-muted:#AEB8C8;--head-text:#E8ECF2;
--amber-bg:#FFE4BF;--amber-fg:#7A3E00;--ok-bg:#E7F6EE;--ok-fg:#0B5A31;--bad-bg:#FDE8E6;--bad-fg:#7A1A12;--bad-line:#F4B7B0;--mono:Consolas,'Cascadia Mono',monospace}
*{box-sizing:border-box}
body{margin:0;font:14px/1.4 'Segoe UI',Arial,sans-serif;color:var(--text);background:var(--surface)}
a{color:var(--blue-deep)}
header{background:var(--ink);color:var(--head-text);padding:12px 24px;display:flex;flex-wrap:wrap;gap:16px;align-items:center}
.brand{display:flex;align-items:center;gap:14px}
.brand svg{height:20px;width:75px}
.vsep{width:1px;height:24px;background:var(--head-line)}
.brand-text{display:flex;flex-direction:column}
header h1{font-size:18px;font-weight:600;margin:0;color:#fff}
.sub{font-size:12px;color:var(--head-muted)}
.grow{flex:1 1 0}
header input{height:36px;padding:0 10px;border:1px solid var(--head-line);border-radius:6px;width:140px;background:#fff;color:var(--text);font:inherit}
header button{height:36px;padding:0 14px;background:transparent;color:var(--head-text);border:1px solid var(--head-line);border-radius:6px}
header button:hover{filter:none;background:#1C2842}
#aeos-url{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid var(--head-line);border-radius:6px;font-size:12px;color:var(--head-muted)}
#aeos-url::before{content:'';width:8px;height:8px;border-radius:50%;background:#7BE0A8}
#login-state{font-weight:600;color:#fff;margin-right:8px}
#login-msg{color:#FFB4AB;font-weight:600}
.chip{display:none;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;font-size:12px;font-weight:600;background:var(--tint);color:var(--blue-dark)}
.chip.chip-trial{background:var(--tint);color:var(--blue-dark)}
.chip.chip-ok{background:var(--ok-bg);color:var(--ok-fg)}
.chip.chip-bad{background:var(--bad-bg);color:var(--bad-fg);font-weight:700}
#banners div{padding:12px 24px;font-weight:600;display:flex;align-items:center;gap:10px}
#banners div::before{content:'';flex:0 0 18px;height:18px;background:center/contain no-repeat url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23131C30' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z'/%3E%3Cline x1='12' y1='9' x2='12' y2='13'/%3E%3Cline x1='12' y1='17' x2='12.01' y2='17'/%3E%3C/svg%3E")}
.warn{background:var(--amber-bg);color:var(--amber-fg);border-bottom:1px solid #F0C98A}
.err{background:var(--bad-bg);color:var(--bad-fg);border-bottom:1px solid var(--bad-line)}
nav{display:flex;flex-wrap:wrap;gap:4px;padding:0 24px;background:#fff;border-bottom:1px solid var(--line)}
nav button{height:48px;padding:0 18px;background:transparent;border:none;border-bottom:3px solid transparent;color:var(--muted);cursor:pointer;border-radius:0}
nav button:hover{filter:none;color:var(--ink)}
nav button.active{border-bottom-color:var(--blue-deep);color:var(--ink);font-weight:600}
.panel{display:none;background:#fff;margin:20px auto;width:calc(100% - 48px);max-width:1360px;padding:20px 24px;border:1px solid var(--line);border-radius:8px;min-height:300px}
.panel.active{display:block}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
#door-counts{display:flex;flex-wrap:wrap;gap:6px;font-size:12px;font-weight:600}
#door-counts span{padding:4px 10px;border-radius:999px;background:#fff;border:1px solid var(--line);color:var(--text)}
#door-counts span.s-locked{background:var(--ink);color:#fff;border-color:var(--ink)}
#door-counts span.s-unlocked{background:var(--amber-bg);color:var(--amber-fg);border-color:var(--amber-bg)}
#door-counts span.s-normal{background:#E6EEFF;color:var(--blue-dark);border-color:#E6EEFF}
#door-counts span.s-unknown{background:#EDEFF3;color:#4A5563;border-color:#EDEFF3}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #ECEEF2;padding:10px 8px;text-align:left;vertical-align:middle}
th{background:#F7F8FA;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;font-weight:600;border-bottom:1px solid var(--line)}
#doors-body td:nth-child(2){font-weight:600;color:var(--ink)}
tr.picked{background:#F3F7FF}
button{font:inherit;cursor:pointer;height:36px;padding:0 14px;background:#fff;color:var(--ink);border:1px solid var(--field);border-radius:6px}
button:hover{filter:brightness(.96)}
button.primary{background:var(--blue-deep);color:#fff;border:none;font-weight:600;height:40px;padding:0 16px}
button.act{margin-right:6px;height:30px;padding:0 10px;font-size:13px}
.pager{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:8px 0;font-size:13px}
.pager button{height:30px;padding:0 10px;font-size:13px}
.pager select{height:30px}
.pager button.pg-link{border:none;background:none;color:var(--blue-dark);text-decoration:underline;padding:0 4px}
button:disabled{opacity:.5;cursor:default}
button svg{vertical-align:-3px;margin-right:6px}
.result.ok{color:#0a6b2a;font-weight:600}
.result.bad{color:var(--red);font-weight:600}
td.state{white-space:nowrap}
.schip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700}
.schip svg{flex:0 0 14px}
.schip.s-locked{background:var(--ink);color:#fff}
.schip.s-unlocked{background:var(--amber-bg);color:var(--amber-fg)}
.schip.s-normal{background:#E6EEFF;color:var(--blue-dark)}
.schip.s-unknown{background:#EDEFF3;color:#4A5563}
#batch-bar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:12px 0;padding:10px 14px;background:var(--tint);border:1px solid var(--tint-line);border-radius:8px}
#batch-count{color:var(--ink);margin-right:6px}
#batch-buttons{display:contents}
#batch-bar button[data-batch=lock]{background:var(--ink);color:#fff;border:none;font-weight:600}
button.lockdown{margin-left:auto;background:var(--red);color:#fff;border:none;font-weight:700;height:40px;padding:0 18px}
fieldset{margin:0 0 14px;border:1px solid var(--line);border-radius:8px;padding:12px 16px}
legend{font-weight:600;color:var(--ink);padding:0 6px}
label{display:inline-block;margin:3px 12px 3px 0}
label span{display:block;font-size:12px;color:var(--muted)}
input[type=text],input[type=number],input[type=password],select,textarea{padding:7px 9px;border:1px solid var(--field);border-radius:6px;font:inherit}
input[type=text]:focus,input[type=number]:focus,select:focus,textarea:focus{outline:2px solid var(--blue);outline-offset:-1px}
#door-filter{height:40px;min-width:260px}
textarea{width:100%;min-height:80px;font:12px var(--mono)}
pre{background:#101820;color:#d8e4f0;padding:10px;overflow:auto;max-height:480px;font:12px var(--mono);white-space:pre-wrap;word-break:break-all;border-radius:6px}
.msg{margin:8px 0;min-height:20px}
.msg.bad{color:var(--red);font-weight:600}
.msg.good{color:#0a6b2a;font-weight:600}
.setup-bar{position:sticky;bottom:0;background:#fff;border-top:1px solid var(--line);padding:2px 0;z-index:5}
.setup-bar p{margin:6px 0}
#fs-license{padding:20px 24px;max-width:760px}
#fs-license h2{margin:0 0 12px;font-size:18px;font-weight:600;color:var(--ink)}
#lic-status{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:6px;font-weight:600;background:var(--tint);color:var(--blue-dark);margin:0 0 14px}
#lic-status.lic-ok{background:var(--ok-bg);color:var(--ok-fg)}
#lic-status.lic-bad{background:var(--bad-bg);color:var(--bad-fg)}
.kv{display:grid;grid-template-columns:180px minmax(0,1fr);row-gap:10px;column-gap:16px;margin:0 0 14px}
.kv .k{color:var(--muted)}
.kv code,#lic-host{font:13px var(--mono);background:var(--surface);padding:3px 8px;border-radius:4px}
#lic-details table{margin:0 0 14px}
#lic-details th{background:transparent;text-transform:none;letter-spacing:0;font-size:14px;width:180px;border:none;padding:4px 16px 4px 0}
#lic-details td{border:none;padding:4px 0}
#btn-import-license{height:44px;padding:0 18px;background:var(--blue-deep);color:#fff;border:none;font-weight:600}
.dlg{display:none;position:fixed;inset:0;background:rgba(19,28,48,.55);align-items:center;justify-content:center;z-index:10}
.dlg .box{background:#fff;border-radius:10px;overflow:hidden;min-width:320px;max-width:560px;width:92%;box-shadow:0 24px 60px rgba(0,0,0,.35)}
.dlg .box-head{background:var(--ink);color:#fff;padding:14px 24px}
.dlg .box-head h2{margin:0;font-size:18px;font-weight:600}
.dlg .box.danger .box-head{background:var(--red)}
.dlg .box.danger .box-head h2{font-weight:700;font-size:20px}
.dlg .box-body{padding:18px 24px}
.dlg .row{padding:6px 24px 20px;text-align:right}
.dlg .row button{height:44px;padding:0 18px;margin-left:10px}
.dlg .box.danger #confirm-ok{background:var(--red);color:#fff;border:none;font-weight:700}
#confirm-ok{background:var(--blue-deep);color:#fff;border:none;font-weight:600}
#about .kv{margin:0}
#doors-layout{display:flex;gap:16px;align-items:flex-start}
#doors-main{flex:1 1 0;min-width:0}
#loc-side{flex:0 0 360px;max-width:360px;border:1px solid var(--line);border-radius:8px;padding:10px 12px;background:#fff}
#loc-side h3{margin:0 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
#groups-panel{margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.grp{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:4px 0}
.grp .grp-name{flex:1 1 100%;color:var(--ink)}
.grp .grp-count{color:var(--muted);font-size:12px;margin-right:4px}
.loc-ul{list-style:none;margin:0;padding-left:14px}
#loc-tree>.loc-ul{padding-left:0}
.loc-row{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:3px 4px;border-radius:6px}
.loc-row.node-on{background:var(--tint);outline:1px solid var(--tint-line)}
button.loc-name{height:26px;padding:0 8px;border:none;background:transparent;font-weight:600;color:var(--ink);text-align:left}
button.loc-name:hover{background:var(--tint)}
.loc-sum{font-size:12px;color:var(--muted);flex:1 1 auto}
button.arm-btn{height:26px;padding:0 8px;font-size:12px}
#btn-arm,#btn-disarm{height:36px;padding:0 14px;font-size:14px}
#btn-arm{background:var(--ink);color:#fff;border:none;font-weight:600}
#loc-filter-note{margin:0 0 8px;font-size:12px;color:var(--blue-dark)}
#arm-report{margin:12px 0;padding:12px 16px;background:#fff;border:1px solid var(--tint-line);border-radius:8px}
#arm-report h3{margin:0 0 6px;font-size:16px;color:var(--ink)}
#arm-report .rep-sum{margin:4px 0;font-weight:600}
#arm-report table{margin:8px 0}
.hint{margin:4px 0 8px;font-size:12px;color:#52606f}
.loc-out{font:12px var(--mono);background:var(--surface);padding:8px;border-radius:6px;margin:6px 0;min-height:20px}
.grp-edit{display:flex;flex-wrap:wrap;align-items:flex-end;gap:6px;padding:6px 0;border-bottom:1px solid #ECEEF2}
.grp-edit .grp-matches{font-size:12px;color:var(--muted);align-self:center}
@media(max-width:1000px){#doors-layout{flex-direction:column}#loc-side{flex:1 1 auto;max-width:none;width:100%}}
</style>
</head>
<body>
<div id="banners"></div>
<header>
  <div class="brand">
    <svg viewBox="0 0 688 183" role="img" aria-label="IT42">
      <path fill="#FFFFFF" fill-rule="evenodd" d="M39.9,168.9 L13.9,168.9 L13.9,14.9 L39.9,14.9 Z M224.4,39.4 L154.9,39.4 L154.9,168.4 L127.9,168.4 L127.9,39.4 L58.4,39.4 L58.4,13.9 L224.4,13.9 Z"></path>
      <path fill="#4B8BFF" fill-rule="evenodd" d="M271.9,14.9 L271.9,91.4 L281.4,100.9 L429.4,100.9 L429.4,15.4 L455.4,15.4 L455.4,168.4 L428.4,168.4 L428.4,124.9 L265.9,124.9 L244.9,103.9 L244.9,14.9 Z M477.4,14.9 L652.5,14.9 L674.5,37.4 L674.5,82.9 L653.0,104.9 L511.4,104.9 L503.9,112.4 L503.9,143.4 L667.5,143.4 L671.5,147.4 L671.5,168.4 L476.9,168.4 L476.9,103.9 L500.9,79.9 L640.0,79.9 L649.0,70.9 L649.0,48.4 L639.0,38.4 L477.4,38.4 Z"></path>
    </svg>
    <span class="vsep"></span>
    <div class="brand-text"><h1>DoorKeeper</h1><span class="sub">Door console for access control systems</span></div>
  </div>
  <span id="aeos-url"></span>
  <span class="grow"></span>
  <span id="lic-chip" class="chip"></span>
  <span id="login-box">
    <input type="text" id="user" placeholder="AEOS user" autocomplete="off">
    <input type="password" id="password" placeholder="Password" autocomplete="off">
    <button id="btn-login">Log in</button>
  </span>
  <span id="logout-box" style="display:none"><span id="login-state"></span> <button id="btn-logout">Log out</button></span>
  <span id="login-msg"></span>
  <button id="btn-about" type="button">About</button>
</header>
<nav>
  <button class="tab active" data-tab="doors">Doors</button>
  <button class="tab" data-tab="setup">Setup</button>
  <button class="tab" data-tab="raw">Raw call</button>
  <button class="tab" data-tab="audit">Audit</button>
  <button class="tab" data-tab="debug">Debug</button>
</nav>

<div class="panel active" id="tab-doors">
  <div class="toolbar">
    <button id="btn-load-doors" class="primary">Load doors</button>
    <button id="btn-refresh-state" style="display:none"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.64-6.36"></path><polyline points="21 3 21 9 15 9"></polyline></svg>Refresh state</button>
    <input type="text" id="door-filter" placeholder="Filter doors">
    <span id="door-counts"></span>
  </div>
  <div class="msg" id="doors-msg"></div>
  <div id="batch-bar" style="display:none"><b id="batch-count">0 selected</b> <span id="batch-buttons"></span> <span id="arm-buttons"><button id="btn-arm" class="arm-btn sel-arm" data-kind="arm" type="button">Arm selected</button> <button id="btn-disarm" class="arm-btn sel-arm" data-kind="disarm" type="button">Disarm selected</button></span> <button id="btn-lockdown" class="lockdown"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>Lockdown</button></div>
  <div id="arm-report" style="display:none">
    <h3 id="arm-report-title"></h3>
    <div class="rep-sum" id="arm-report-sum"></div>
    <div id="arm-report-state"></div>
    <div class="msg" id="arm-report-note"></div>
    <table id="arm-report-table"><thead><tr><th>Failed door</th><th>Location</th><th>Reply / fault</th><th>State after</th></tr></thead><tbody id="arm-report-failed"></tbody></table>
    <button id="arm-retry" type="button">Retry failed</button>
    <button id="arm-export" type="button">Export CSV</button>
    <button id="arm-close" type="button">Close report</button>
  </div>
  <div id="doors-layout">
    <aside id="loc-side" style="display:none">
      <div id="groups-panel" style="display:none"><h3>Door groups</h3><div id="groups-list"></div></div>
      <div id="loc-tree-box"><h3>Locations</h3>
        <div id="loc-filter-note" style="display:none"><span id="loc-filter-text"></span> <button id="loc-filter-clear" type="button">Show all doors</button></div>
        <div id="loc-tree"></div></div>
    </aside>
    <div id="doors-main"><div id="pager-top" class="pager" style="display:none"></div><table><thead id="doors-head"></thead><tbody id="doors-body"></tbody></table><div id="pager-bottom" class="pager" style="display:none"></div></div>
  </div>
</div>

<div class="panel" id="tab-setup">
  <fieldset id="fs-license"><h2>License</h2>
    <p id="lic-status"></p>
    <div id="lic-details"></div>
    <div class="kv">
      <span class="k">AEOS host of this console (send it to your supplier)</span>
      <span><b id="lic-host"></b> <button id="btn-copy-host" type="button">Copy</button></span>
      <span class="k">Doors in the list</span><span id="lic-doors">0</span>
      <span class="k">Product version</span><span id="lic-version"></span>
    </div>
    <p><label><span>License file (license.json)</span><input type="file" id="lic-file" accept=".json,application/json"></label>
    <button id="btn-import-license" type="button">Import license file</button></p>
    <div class="msg" id="lic-msg"></div>
  </fieldset>
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
  <fieldset id="fs-socket"><legend>Socket interface (door commands over TCP)</legend>
    <label><span>Host (empty = host of the AEOS URL)</span><input type="text" id="sk-host" size="30"></label>
    <label><span>Port</span><input type="number" id="sk-port" min="0" max="65535" style="width:90px"></label>
    <label><span>Line terminator</span><select id="sk-terminator"><option value="CRLF">CRLF</option><option value="LF">LF</option></select></label>
    <label><span>Greeting wait (ms)</span><input type="number" id="sk-greetingWaitMs" min="0" max="60000" style="width:90px"></label>
    <label><span>Reply timeout (s)</span><input type="number" id="sk-replyTimeoutSec" min="1" max="120" style="width:90px"></label><br>
    <label><input type="checkbox" id="sk-tls"> Use TLS</label>
    <label><input type="checkbox" id="sk-tlsSkipValidation"> Skip TLS certificate validation (self-signed server; shows a warning)</label><br>
    <label><span>Login command ({{user}} {{password}} = the user and password typed at the top of the page)</span><input type="text" id="sk-loginTemplate" size="50"></label>
    <label><span>Login success pattern (regex on the reply line; empty = any reply)</span><input type="text" id="sk-loginSuccessPattern" size="30"></label>
    <label style="display:block"><span>Init commands (one per line, each sent after the login; one reply line is read for each)</span><textarea id="sk-initCommands" style="min-height:44px"></textarea></label>
  </fieldset>
  <div id="setup-doorstate"></div>
  <div id="setup-locations"></div>
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
  <hr>
  <p><b>Socket command</b> (uses the Socket interface settings: connect, login, init commands, then this one command; the replies are shown)</p>
  <label style="display:block"><span>Command (one line, sent as typed)</span><input type="text" id="raw-socket-cmd" size="70"></label>
  <p><button id="btn-raw-socket-send">Send socket command</button></p>
  <div class="msg" id="raw-socket-msg"></div>
  <pre id="raw-socket-out"></pre>
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

<div id="confirm" class="dlg" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
  <div class="box" id="confirm-box"><div class="box-head"><h2 id="confirm-title">Please confirm</h2></div>
  <div class="box-body"><div id="confirm-msg"></div></div>
  <div class="row"><button id="confirm-cancel">Cancel</button><button id="confirm-ok">OK</button></div></div>
</div>

<div id="about" class="dlg" role="dialog" aria-modal="true" aria-labelledby="about-title">
  <div class="box"><div class="box-head"><h2 id="about-title">About DoorKeeper</h2></div>
  <div class="box-body"><div class="kv">
    <span class="k">Product</span><span id="about-product">DoorKeeper</span>
    <span class="k">Version</span><span id="about-version"></span>
    <span class="k">License</span><span id="about-license"></span>
    <span class="k">Made by</span><span>IT42 d.o.o. - it42.hr</span>
  </div></div>
  <div class="row"><button id="about-close">Close</button></div></div>
</div>

<script>
(function(){
'use strict';
var TOKEN=document.querySelector('meta[name="console-token"]').getAttribute('content');
var ACTIONS=['listDoors','lock','unlock','access','normal'];
var DOOR_ACTIONS=['lock','unlock','access','normal'];
var CFG=null,LIC=null,OPS=[],DOORS=[],debugTimer=null,SEL={},STATES={},RES={},BATCH_BUSY=false,DS_ROWS=4;
var PLACE={},NODES={},TREE_DOORS=null,TREE_LOC='',LOCFILTER='',ARMREP=null;
/* Doors table pager: PAGESIZE 0 = all rows; kept per browser (the page works without storage) */
var PAGE_SIZES=[25,50,100,250,500,0],PAGE=1,PAGEKEY='',PAGEROWS=[];
var PAGESIZE=(function(){try{var v=parseInt(localStorage.getItem('dk-rows-per-page'),10);if(PAGE_SIZES.indexOf(v)>=0){return v;}}catch(e){}return 100;})();
function $(id){return document.getElementById(id);}
function h(tag,attrs,kids){
  var e=document.createElement(tag);
  if(attrs){Object.keys(attrs).forEach(function(k){
    if(k==='text'){e.textContent=attrs[k];}else if(k==='class'){e.className=attrs[k];}else{e.setAttribute(k,attrs[k]);}
  });}
  (kids||[]).forEach(function(c){e.appendChild(typeof c==='string'?document.createTextNode(c):c);});
  return e;
}
function api(method,path,body,rawText){
  var opt={method:method,headers:{'X-Console-Token':TOKEN}};
  if(body!==undefined){opt.headers['Content-Type']='application/json';opt.body=rawText?body:JSON.stringify(body);}
  return fetch(path,opt).then(function(r){
    return r.text().then(function(txt){
      var j=null;try{j=JSON.parse(txt);}catch(e){}
      var rid=(j&&j.requestId)||r.headers.get('X-Request-Id')||'-';
      if(!r.ok){
        var msg=(j&&j.error&&j.error.message)||('HTTP '+r.status);
        if(r.status===403&&msg.indexOf('X-Console-Token')>=0){
          // DoorKeeper was restarted and issued a new page key: this page is from the earlier run. Reload it once
          // (a guard stops a reload loop if the key still does not match).
          var last=0;try{last=parseInt(sessionStorage.getItem('dk-stale-reload')||'0',10)||0;}catch(e){}
          if(Date.now()-last>10000){try{sessionStorage.setItem('dk-stale-reload',String(Date.now()));}catch(e){}location.reload();}
          msg='DoorKeeper was restarted, so this page was out of date and reloads itself. If this message stays, open '+location.origin+'/ again.';
        }
        var er=new Error(msg);
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
function confirmDialog(msg,opts){
  opts=opts||{};
  return new Promise(function(res){
    var d=$('confirm');$('confirm-msg').textContent=msg;
    $('confirm-title').textContent=opts.title||'Please confirm';
    $('confirm-ok').textContent=opts.ok||'OK';
    $('confirm-box').className='box'+(opts.danger?' danger':'');
    d.style.display='flex';$('confirm-ok').focus();
    function done(v){d.style.display='none';$('confirm-ok').onclick=null;$('confirm-cancel').onclick=null;res(v);}
    $('confirm-ok').onclick=function(){done(true);};
    $('confirm-cancel').onclick=function(){done(false);};
  });
}

/* ---- about ---- */
function openAbout(){
  var v=document.querySelector('meta[name="console-version"]');
  $('about-version').textContent=v?v.getAttribute('content'):'';
  $('about-license').textContent=licLine();
  $('about').style.display='flex';$('about-close').focus();
}
$('btn-about').onclick=openAbout;
$('about-close').onclick=function(){$('about').style.display='none';};
$('about').onclick=function(e){if(e.target===$('about')){$('about').style.display='none';}};

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
function isMapped(def){
  if(!def){return false;}
  return (def.transport==='socket')?!!def.command:!!def.operation;
}
function socketInUse(){
  return DOOR_ACTIONS.some(function(a){return CFG.actions[a]&&CFG.actions[a].transport==='socket'&&CFG.actions[a].command;});
}
function renderBanners(){
  var b=$('banners');b.innerHTML='';
  if(CFG&&CFG.tlsSkipValidation){b.appendChild(h('div',{class:'warn',text:'WARNING: TLS certificate validation is OFF. The AEOS server identity is not checked.'}));}
  if(CFG&&CFG.socket&&CFG.socket.tlsSkipValidation){b.appendChild(h('div',{class:'warn',text:'WARNING: TLS certificate validation is OFF for the socket interface. The AEOS server identity is not checked.'}));}
  if(CFG&&CFG.socket&&CFG.socket.tls===false&&socketInUse()){b.appendChild(h('div',{class:'warn',text:'WARNING: the socket interface is used without TLS. The password is sent unencrypted.'}));}
  if(CFG&&/^http:/i.test(CFG.aeosUrl||'')){b.appendChild(h('div',{class:'warn',text:'WARNING: the AEOS URL is plain http. The password is sent unencrypted.'}));}
  if(LIC&&!LIC.actionsAllowed){
    var hostTxt=LIC.aeosHost?(' AEOS host to send to your supplier: '+LIC.aeosHost+'.'):'';
    b.appendChild(h('div',{class:'err',id:'lic-banner',text:'Door actions are switched off. '+LIC.reason+hostTxt}));
  }
  $('aeos-url').textContent=(CFG&&CFG.aeosUrl)?CFG.aeosUrl:'(AEOS URL not set - open Setup)';
}
/* ---- license ---- */
function licBlocked(){return !!(LIC&&!LIC.actionsAllowed);}
function licTip(){return licBlocked()?('Switched off: '+LIC.reason):'';}
var SVG_O='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';
var ICON_OK=SVG_O+'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>';
var ICON_CLOCK=SVG_O+'<circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>';
var ICON_BAD=SVG_O+'<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
var STATE_ICONS={
  locked:SVG_O+'<rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
  unlocked:SVG_O+'<rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>',
  normal:ICON_OK,
  unknown:SVG_O+'<circle cx="12" cy="12" r="10"></circle><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
};
function stateKind(label){var l=String(label||'').toLowerCase();return (l==='locked'||l==='unlocked'||l==='normal')?l:'unknown';}
function chipText(){
  if(!LIC){return '';}
  if(LIC.state==='trial'){return 'Trial - '+LIC.daysLeft+' day'+(LIC.daysLeft===1?'':'s')+' left';}
  if(LIC.state==='licensed'){return 'Licensed';}
  if(LIC.state==='expired'){return LIC.details?'License expired':'Trial ended';}
  return 'License invalid';
}
// One status line: a trial's reason only repeats the chip ("N day(s) left"), so it is left out there.
function licLine(){
  if(!LIC){return 'License status unknown.';}
  return LIC.state==='trial'?(chipText()+'.'):(chipText()+'. '+LIC.reason);
}
function renderLicense(){
  var chip=$('lic-chip');
  if(LIC){
    chip.innerHTML=(LIC.state==='licensed'?ICON_OK:(LIC.state==='trial'?ICON_CLOCK:ICON_BAD));
    chip.appendChild(document.createTextNode(chipText()));
    chip.className='chip '+(LIC.state==='licensed'?'chip-ok':(LIC.state==='trial'?'chip-trial':'chip-bad'));
    chip.style.display='inline-flex';chip.title=LIC.reason;
  }
  var ls=$('lic-status');
  ls.className=LIC?(LIC.state==='licensed'?'lic-ok':(LIC.state==='trial'?'':'lic-bad')):'';
  ls.textContent=licLine();
  $('lic-doors').textContent=String(DOORS.length);
  (function(){var v=document.querySelector('meta[name="console-version"]');$('lic-version').textContent=v?v.getAttribute('content'):'';})();
  var d=$('lic-details');d.innerHTML='';
  if(LIC&&LIC.state==='licensed'&&LIC.details){
    var t=LIC.details;
    var rows=[['Licensed to',t.customer+' ('+t.site+')'],['License id',t.licenseId],['Type',t.type],['AEOS hosts',(t.aeosHosts||[]).join(', ')],
      ['Doors allowed',t.maxDoors>0?String(t.maxDoors):'unlimited'],['Issued',t.issued],['Expires',t.expires||'never']];
    d.appendChild(h('table',null,rows.map(function(r){return h('tr',null,[h('th',{text:r[0]}),h('td',{text:r[1]})]);})));
  }
  $('lic-host').textContent=(LIC&&LIC.aeosHost)?LIC.aeosHost:'(AEOS URL not set - open Setup)';
  $('btn-copy-host').disabled=!(LIC&&LIC.aeosHost);
  ['btn-raw-send','btn-raw-socket-send'].forEach(function(id){$(id).disabled=licBlocked();$(id).title=licTip();});
  renderBanners();renderDoors();
}
function loadLicense(){
  return api('GET','/api/v1/license').then(function(r){LIC=r;renderLicense();}).catch(function(e){LIC=null;renderLicense();setMsg('lic-msg','License status not read: '+errText(e),'bad');});
}
$('btn-copy-host').onclick=function(){
  var txt=(LIC&&LIC.aeosHost)||'';if(!txt){return;}
  function ok(){setMsg('lic-msg','Copied: '+txt,'good');}
  function fallback(){
    var ta=h('textarea',{style:'position:fixed;left:-1000px'});ta.value=txt;document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');ok();}catch(e){setMsg('lic-msg','Copy failed. Select the host and copy it by hand.','bad');}
    ta.remove();
  }
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(ok,fallback);}else{fallback();}
};
$('btn-import-license').onclick=function(){
  var f=$('lic-file').files&&$('lic-file').files[0];
  if(!f){setMsg('lic-msg','Choose the license file (license.json) first.','bad');return;}
  setMsg('lic-msg','Checking the license file...');
  f.text().then(function(text){return api('PUT','/api/v1/license',text,true);}).then(function(r){
    LIC=r;renderLicense();setMsg('lic-msg','License imported and saved (request id '+r._rid+').','good');
  }).catch(function(e){setMsg('lic-msg','License file refused: '+errText(e),'bad');});
};
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
function stateOn(){return !!(CFG&&CFG.doorState&&CFG.doorState.checks&&CFG.doorState.checks.length);}
function slim(d){return {id:d.id,name:d.name,extra:d.extra||{}};}
/* ---- locations: JS twin of Get-DoorLocation / Test-DoorInGroup on the server (tests\fixtures\locations.json feeds both) ---- */
function hasOwn(o,k){return Object.prototype.hasOwnProperty.call(o,k);}
function placeDoor(d,loc){
  var fields={},rule=0,extra=d.extra||{};
  var levels=((loc&&loc.levels)||[]).map(String).filter(function(x){return x;});
  if(loc){
    var rules=loc.rules||[];
    for(var i=0;i<rules.length;i++){
      var r=rules[i];
      if(!r||!r.pattern){continue;}
      var val=(r.source==='name')?d.name:((r.source==='id')?d.id:(hasOwn(extra,r.source)?extra[r.source]:''));
      val=(val===undefined||val===null)?'':String(val);
      if(!val){continue;}
      var re=null;try{re=new RegExp(r.pattern);}catch(e){continue;}
      var m=re.exec(val);
      if(!m){continue;}
      var g=m.groups||{};
      Object.keys(g).forEach(function(k){if(g[k]){fields[k]=g[k];}});
      rule=i+1;break;
    }
    var map=loc.map||{};
    var keys=[String(d.id),String(d.name)];
    Object.keys(extra).forEach(function(k){keys.push(String(extra[k]));});
    for(var j=0;j<keys.length;j++){
      if(!keys[j]||!hasOwn(map,keys[j])){continue;}
      var ent=map[keys[j]]||{};
      Object.keys(ent).forEach(function(k){if(ent[k]){fields[k]=String(ent[k]);}});
      break;
    }
  }
  var path=[];
  for(var q=0;q<levels.length;q++){if(fields[levels[q]]){path.push(fields[levels[q]]);}else{break;}}
  return {fields:fields,path:path,placed:path.length>0,text:path.length?path.join('/'):'(unplaced)',rule:rule};
}
function doorInGroup(d,pl,g){
  if(!g){return false;}
  var ids=[].concat(g.doorIds||[]);
  for(var i=0;i<ids.length;i++){if(ids[i]!==null&&ids[i]!==undefined&&String(ids[i])===String(d.id)){return true;}}
  var m=g.match||{},used=0,all=true;
  Object.keys(m).forEach(function(k){
    var vals=[].concat((m[k]===null||m[k]===undefined)?[]:m[k]).filter(function(x){return x!==null&&x!==undefined&&String(x)!=='';}).map(String);
    if(!vals.length){return;}
    used++;
    if(vals.indexOf(pl.fields[k]||'')<0){all=false;}
  });
  return used>0&&all;
}
function locLevels(){return ((CFG&&CFG.locations&&CFG.locations.levels)||[]).filter(function(x){return x;});}
function labelOf(v){var lb=CFG&&CFG.locations&&CFG.locations.labels;return (lb&&hasOwn(lb,v)&&lb[v])?String(lb[v]):v;}
function pathName(path){return path.map(labelOf).join(' / ');}
function placeAll(){PLACE={};var loc=CFG&&CFG.locations;DOORS.forEach(function(d){PLACE[d.id]=placeDoor(d,loc);});}
function groupDoors(g){return DOORS.filter(function(d){return PLACE[d.id]&&doorInGroup(d,PLACE[d.id],g);});}
function stateSummary(ids){
  if(!stateOn()){return '';}
  var n={},order=['Locked','Unlocked','Normal'];
  ids.forEach(function(id){var st=STATES[id];if(st){n[st.state]=(n[st.state]||0)+1;}});
  var keys=Object.keys(n).sort(function(a,b){var x=order.indexOf(a),y=order.indexOf(b);x=x<0?99:x;y=y<0?99:y;return x!==y?x-y:(a<b?-1:1);});
  return keys.map(function(k){return n[k]+' '+k;}).join(', ');
}
function visibleDoors(){
  var f=$('door-filter').value.toLowerCase();
  var set=(LOCFILTER&&NODES[LOCFILTER])?NODES[LOCFILTER].set:null;
  return DOORS.filter(function(d){
    if(set&&!set[d.id]){return false;}
    if(!f){return true;}
    var pl=PLACE[d.id],loc='';
    if(pl){loc=Object.keys(pl.fields).map(function(k){return pl.fields[k]+' '+labelOf(pl.fields[k]);}).join(' ');}
    return (d.name+' '+d.id+' '+loc).toLowerCase().indexOf(f)>=0;
  });
}
function selectedDoors(){return DOORS.filter(function(d){return SEL[d.id];});}
function rowOf(id){
  var rows=$('doors-body').children;
  for(var i=0;i<rows.length;i++){if(rows[i].getAttribute('data-id')===id){return rows[i];}}
  return null;
}
function paintResult(td,rec){
  td.className='result '+(rec.cls||'');td.textContent=rec.text||'';
  if(rec.rid){td.setAttribute('data-rid',rec.rid);}
}
function setRowResult(id,cls,text,rid){
  RES[id]={cls:cls,text:text,rid:rid};
  var row=rowOf(id);if(row){paintResult(row.querySelector('td.result'),RES[id]);}
}
function paintState(td,st){
  var k=stateKind(st.state);
  td.title=st.detail||'';td.className='state'+(st.state==='?'?' unknown':'');
  td.innerHTML='';
  var c=h('span',{class:'schip s-'+k});c.innerHTML=STATE_ICONS[k];c.appendChild(document.createTextNode(st.state));
  td.appendChild(c);
}
function setState(id,state,detail){
  STATES[id]={state:state,detail:detail};
  var row=rowOf(id);if(row){paintState(row.querySelector('td.state'),STATES[id]);}
  renderCounts();
}
function renderCounts(){
  paintTree();
  var box=$('door-counts');box.innerHTML='';
  if(!DOORS.length){return;}
  box.appendChild(h('span',{text:DOORS.length+' doors'}));
  if(!stateOn()){return;}
  var n={locked:0,unlocked:0,normal:0,unknown:0};
  DOORS.forEach(function(d){var st=STATES[d.id];n[st?stateKind(st.state):'unknown']+=1;});
  ['locked','unlocked','normal','unknown'].forEach(function(k){box.appendChild(h('span',{class:'s-'+k,text:n[k]+' '+k}));});
}
function updateBatchBar(){
  var sel=selectedDoors().length;
  $('batch-bar').style.display=DOORS.length?'':'none';
  $('batch-count').textContent=sel+' selected';
  Array.prototype.forEach.call($('batch-buttons').children,function(b){b.disabled=(sel===0)||BATCH_BUSY||licBlocked();b.title=licTip();});
  $('btn-lockdown').style.display=isMapped(CFG&&CFG.actions.lock)?'':'none';
  $('btn-lockdown').disabled=BATCH_BUSY||!DOORS.length||licBlocked();$('btn-lockdown').title=licTip();
  $('btn-refresh-state').style.display=stateOn()?'':'none';
  Array.prototype.forEach.call($('doors-body').children,function(r){r.classList.toggle('picked',!!SEL[r.getAttribute('data-id')]);});
  renderCounts();
  var sa=$('sel-all');
  if(sa){sa.checked=PAGEROWS.length>0&&PAGEROWS.every(function(d){return SEL[d.id];});}
  paintPagerSel();
  paintArm(sel);
}
function renderPager(total,pages){
  ['top','bottom'].forEach(function(w){
    var box=$('pager-'+w);box.innerHTML='';
    if(!DOORS.length){box.style.display='none';return;}
    box.style.display='';
    var s=(w==='top')?'':'-b';
    var first=total?(PAGESIZE?(PAGE-1)*PAGESIZE+1:1):0;
    var last=PAGESIZE?Math.min(PAGE*PAGESIZE,total):total;
    function go(p){return function(){PAGE=p;renderDoors();if(w==='bottom'){$('doors-main').scrollIntoView({block:'start'});}};}
    function btn(id,text,p,off){var b=h('button',{type:'button',id:id+s,text:text});b.onclick=go(p);b.disabled=off;return b;}
    box.appendChild(btn('pg-first','First',1,PAGE<=1));
    box.appendChild(btn('pg-prev','Previous',PAGE-1,PAGE<=1));
    box.appendChild(h('span',{id:'pg-info'+s,text:'Doors '+first+'-'+last+' of '+total+', page '+PAGE+' of '+pages}));
    box.appendChild(btn('pg-next','Next',PAGE+1,PAGE>=pages));
    box.appendChild(btn('pg-last','Last',pages,PAGE>=pages));
    if(w==='top'){
      var sel=h('select',{id:'pg-size'});
      PAGE_SIZES.forEach(function(n){var o=h('option',{value:String(n),text:n?String(n):'All'});o.selected=(n===PAGESIZE);sel.appendChild(o);});
      sel.onchange=function(){PAGESIZE=parseInt(sel.value,10)||0;try{localStorage.setItem('dk-rows-per-page',String(PAGESIZE));}catch(e){}PAGE=1;renderDoors();};
      box.appendChild(h('label',null,['Rows per page ',sel]));
      box.appendChild(h('span',{id:'pg-selnote'}));
    }
  });
}
function paintPagerSel(){
  var box=$('pg-selnote');if(!box){return;}
  box.innerHTML='';
  var vis=visibleDoors();
  if(!PAGEROWS.length||vis.length<=PAGEROWS.length){return;}
  function link(id,text,on){var b=h('button',{type:'button',id:id,'class':'pg-link',text:text});b.onclick=function(){vis.forEach(function(d){SEL[d.id]=on;});renderDoors();};return b;}
  if(vis.every(function(d){return SEL[d.id];})){
    box.appendChild(h('span',{text:'All '+vis.length+' doors in the list are selected.'}));
    box.appendChild(link('pg-clear','Clear selection',false));
  }
  else if(PAGEROWS.every(function(d){return SEL[d.id];})){
    box.appendChild(h('span',{text:'All '+PAGEROWS.length+' doors on this page are selected.'}));
    box.appendChild(link('pg-selall','Select all '+vis.length+' in the list',true));
  }
}
/* ---- arming: Arm = arming.armAction, Disarm = arming.disarmAction (door actions of the Setup tab) ---- */
function armInfo(kind){
  var ar=(CFG&&CFG.arming)||{};
  var key=(kind==='arm')?(ar.armAction||'lock'):(ar.disarmAction||'normal');
  var label=(kind==='arm')?(ar.armLabel||'Arm'):(ar.disarmLabel||'Disarm');
  return {key:key,label:label,mapped:!!(CFG&&CFG.actions&&CFG.actions[key]&&isMapped(CFG.actions[key]))};
}
function paintArm(sel){
  Array.prototype.forEach.call(document.querySelectorAll('button.arm-btn'),function(b){
    var info=armInfo(b.getAttribute('data-kind'));
    var own=b.classList.contains('sel-arm');
    b.textContent=info.label+(own?' selected':'');
    var why='';
    if(licBlocked()){why=licTip();}
    else if(!info.mapped){why='Not available: the "'+info.key+'" action is not mapped on the Setup tab.';}
    b.disabled=!!why||BATCH_BUSY||(own&&sel===0)||b.getAttribute('data-n')==='0';
    b.title=why;
  });
  var rb=$('arm-retry');
  if(rb){rb.disabled=BATCH_BUSY||licBlocked()||!ARMREP||!ARMREP.failed.length;}
}
function selScope(doors){
  if(!locLevels().length){return {name:'the selection',label:'selection of '+doors.length+' doors'};}
  var seen={},names=[],texts=[];
  doors.forEach(function(d){
    var pl=PLACE[d.id];var t=pl?pl.text:'(unplaced)';
    if(!seen[t]){seen[t]=true;texts.push(t);names.push((pl&&pl.placed)?pathName(pl.path):'(unplaced)');}
  });
  return {name:'the selection: '+names.slice(0,3).join('; ')+(names.length>3?'; ...':''),label:'selection: '+texts.slice(0,5).join(', ')+(texts.length>5?', ...':'')};
}
function armRun(kind,doors,scope){
  var info=armInfo(kind);
  if(!doors.length||!info.mapped){return;}
  runBatch(info.key,doors,info.label+' '+doors.length+' door(s) in '+scope.name+'?',{title:info.label,ok:info.label},
    {report:{label:scope.label},kindLabel:info.label,scopeName:scope.name,reportLabel:scope.label});
}
function applySel(ids,val){
  ids.forEach(function(id){SEL[id]=val;var row=rowOf(id);if(row){row.querySelector('input.sel').checked=val;}});
  updateBatchBar();
}
function selectOnly(ids){
  SEL={};ids.forEach(function(id){SEL[id]=true;});
  Array.prototype.forEach.call($('doors-body').children,function(r){r.querySelector('input.sel').checked=!!SEL[r.getAttribute('data-id')];});
  updateBatchBar();
}
/* ---- location tree and door groups panel ---- */
function cmpNode(a,b){
  if(a.key==='(unplaced)'){return 1;}
  if(b.key==='(unplaced)'){return -1;}
  return a.path[a.path.length-1].localeCompare(b.path[b.path.length-1],undefined,{numeric:true});
}
function buildTreeData(){
  NODES={};var roots=[];
  function node(path,parent){
    var key=path.join('/');
    if(!NODES[key]){
      var n={key:key,path:path,ids:[],set:{},children:[],level:path.length-1,name:(key==='(unplaced)')?key:labelOf(path[path.length-1])};
      NODES[key]=n;(parent?parent.children:roots).push(n);
    }
    return NODES[key];
  }
  DOORS.forEach(function(d){
    var pl=PLACE[d.id];var path=pl.placed?pl.path:['(unplaced)'];var parent=null;
    for(var i=1;i<=path.length;i++){var n=node(path.slice(0,i),parent);n.ids.push(d.id);n.set[d.id]=true;parent=n;}
  });
  function sortAll(list){list.sort(cmpNode);list.forEach(function(n){sortAll(n.children);});}
  sortAll(roots);
  return roots;
}
function nodeDoors(n){return DOORS.filter(function(d){return n.set[d.id];});}
function renderNode(n){
  var lv=locLevels()[n.level]||'';
  var cb=h('input',{type:'checkbox','class':'loc-cb',title:'Select all doors here'});
  var nm=h('button',{'class':'loc-name',type:'button',text:n.name,title:(lv?(lv+': '):'')+n.path[n.path.length-1]+' - click to show only these doors'});
  var sum=h('span',{'class':'loc-sum'});
  var ar=h('button',{'class':'arm-btn loc-arm',type:'button','data-kind':'arm'});
  var di=h('button',{'class':'arm-btn loc-disarm',type:'button','data-kind':'disarm'});
  var row=h('div',{'class':'loc-row'},[cb,nm,sum,ar,di]);
  n.cb=cb;n.sum=sum;n.row=row;
  cb.onchange=function(){applySel(n.ids,cb.checked);};
  nm.onclick=function(){LOCFILTER=(LOCFILTER===n.key)?'':n.key;renderDoors();};
  var scope={name:(n.key==='(unplaced)')?'the doors without a location':pathName(n.path),label:'location: '+n.key};
  ar.onclick=function(){armRun('arm',nodeDoors(n),scope);};
  di.onclick=function(){armRun('disarm',nodeDoors(n),scope);};
  var li=h('li',{'data-path':n.key},[row]);
  if(n.children.length){
    var ul=h('ul',{'class':'loc-ul'});
    n.children.forEach(function(c){ul.appendChild(renderNode(c));});
    li.appendChild(ul);
  }
  return li;
}
function renderTree(){
  var box=$('loc-tree');box.innerHTML='';
  TREE_DOORS=DOORS;TREE_LOC=JSON.stringify((CFG&&CFG.locations)||null);
  NODES={};
  if(!locLevels().length||!DOORS.length){return;}
  var ul=h('ul',{'class':'loc-ul'});
  buildTreeData().forEach(function(n){ul.appendChild(renderNode(n));});
  box.appendChild(ul);
}
function paintTree(){
  Object.keys(NODES).forEach(function(k){
    var n=NODES[k];if(!n.cb){return;}
    var sel=0;n.ids.forEach(function(id){if(SEL[id]){sel++;}});
    n.cb.checked=sel>0&&sel===n.ids.length;n.cb.indeterminate=sel>0&&sel<n.ids.length;
    var s=stateSummary(n.ids);
    n.sum.textContent=n.ids.length+' door'+(n.ids.length===1?'':'s')+(s?(' - '+s):'');
    n.row.classList.toggle('node-on',LOCFILTER===k);
  });
  var note=$('loc-filter-note');
  if(note){
    var on=!!(LOCFILTER&&NODES[LOCFILTER]);
    note.style.display=on?'':'none';
    if(on){$('loc-filter-text').textContent='Showing only: '+((LOCFILTER==='(unplaced)')?LOCFILTER:pathName(NODES[LOCFILTER].path));}
  }
}
function renderGroups(){
  var box=$('groups-list');box.innerHTML='';
  var gs=(CFG&&CFG.groups)||[];
  $('groups-panel').style.display=(gs.length&&DOORS.length)?'':'none';
  gs.forEach(function(g){
    var ds=groupDoors(g);
    var scope={name:'group "'+g.name+'"',label:'group: '+g.name};
    var sel=h('button',{'class':'grp-select',type:'button',text:'Select',title:'Select only the doors of this group'});
    var ar=h('button',{'class':'arm-btn grp-arm',type:'button','data-kind':'arm','data-n':String(ds.length)});
    var di=h('button',{'class':'arm-btn grp-disarm',type:'button','data-kind':'disarm','data-n':String(ds.length)});
    sel.onclick=function(){selectOnly(ds.map(function(d){return d.id;}));};
    ar.onclick=function(){armRun('arm',ds,scope);};
    di.onclick=function(){armRun('disarm',ds,scope);};
    box.appendChild(h('div',{'class':'grp','data-group':g.name},[h('b',{'class':'grp-name',text:g.name}),
      h('span',{'class':'grp-count',text:ds.length+' door'+(ds.length===1?'':'s')}),sel,ar,di]));
  });
}
/* ---- arming report ---- */
function showReport(r,doors,a,meta){
  var results=r.results||[];
  var fails=results.filter(function(x){return !x.ok;});
  ARMREP={a:a,meta:meta,failed:fails.map(function(x){return x.id;}),file:r.reportFile||''};
  $('arm-report').style.display='';
  $('arm-report-title').textContent=meta.kindLabel+' - '+meta.scopeName+(meta.retry?' (retry of the failed doors)':'');
  $('arm-report-sum').textContent='Requested '+r.count+', OK '+r.okCount+', failed '+r.failCount+'.';
  var st=stateSummary(results.map(function(x){return x.id;}));
  $('arm-report-state').textContent=st?('State after: '+st):'';
  $('arm-report-note').textContent=r.reportError?('The CSV report could not be written: '+r.reportError):(r.reportFile?('CSV report: '+r.reportFile):'');
  var body=$('arm-report-failed');body.innerHTML='';
  fails.forEach(function(x){
    var pl=PLACE[x.id];
    var stt=STATES[x.id];
    body.appendChild(h('tr',{'data-id':x.id},[h('td',{text:x.name+' ('+x.id+')'}),h('td',{text:pl?pl.text:''}),
      h('td',{text:(x.fault||'no reply')+(x.refused?' (refused, not sent)':'')}),h('td',{text:stt?stt.state:''})]));
  });
  $('arm-report-table').style.display=fails.length?'':'none';
  $('arm-export').disabled=!ARMREP.file;
  paintArm(selectedDoors().length);
}
function renderDoors(){
  var extras=(CFG&&CFG.actions.listDoors.extraFields)||[];
  var levels=locLevels();
  placeAll();
  if(TREE_DOORS!==DOORS||TREE_LOC!==JSON.stringify((CFG&&CFG.locations)||null)){renderTree();}
  if(LOCFILTER&&!NODES[LOCFILTER]){LOCFILTER='';}
  renderGroups();
  $('loc-side').style.display=(DOORS.length&&(levels.length||((CFG&&CFG.groups)||[]).length))?'':'none';
  $('loc-tree-box').style.display=levels.length?'':'none';
  var head=$('doors-head');head.innerHTML='';
  var selAll=h('input',{type:'checkbox',id:'sel-all',title:'Select all doors on this page'});
  var tr=h('tr',null,[h('th',null,[selAll]),h('th',{text:'Name'}),h('th',{text:'Id'})]);
  extras.forEach(function(x){tr.appendChild(h('th',{text:x}));});
  levels.forEach(function(x){tr.appendChild(h('th',{'class':'loc-th','data-level':x,text:x}));});
  if(stateOn()){tr.appendChild(h('th',{text:'State'}));}
  tr.appendChild(h('th',{text:'Actions'}));tr.appendChild(h('th',{text:'Result'}));head.appendChild(tr);
  selAll.onchange=function(){
    PAGEROWS.forEach(function(d){
      SEL[d.id]=selAll.checked;
      var row=rowOf(d.id);if(row){row.querySelector('input.sel').checked=selAll.checked;}
    });
    updateBatchBar();
  };
  var bb=$('batch-buttons');bb.innerHTML='';
  DOOR_ACTIONS.forEach(function(a){
    var def=CFG.actions[a];if(!isMapped(def)){return;}
    var b=h('button',{'data-batch':a,text:(def.label||a)+' selected'});
    b.onclick=function(){
      var ds=selectedDoors();
      runBatch(a,ds,(def.label||a)+' '+ds.length+' selected door(s)?');
    };
    bb.appendChild(b);
  });
  var vis=visibleDoors();
  var key=$('door-filter').value+'|'+LOCFILTER;
  if(key!==PAGEKEY){PAGEKEY=key;PAGE=1;}
  var pages=PAGESIZE?Math.max(1,Math.ceil(vis.length/PAGESIZE)):1;
  if(PAGE>pages){PAGE=pages;}
  if(PAGE<1){PAGE=1;}
  PAGEROWS=PAGESIZE?vis.slice((PAGE-1)*PAGESIZE,PAGE*PAGESIZE):vis;
  renderPager(vis.length,pages);
  var body=$('doors-body');body.innerHTML='';
  PAGEROWS.forEach(function(d){
    var cb=h('input',{type:'checkbox','class':'sel','data-id':d.id});
    cb.checked=!!SEL[d.id];
    cb.onchange=function(){SEL[d.id]=cb.checked;updateBatchBar();};
    var row=h('tr',{'data-id':d.id},[h('td',null,[cb]),h('td',{text:d.name}),h('td',{text:d.id})]);
    extras.forEach(function(x){row.appendChild(h('td',{text:(d.extra&&d.extra[x])||''}));});
    var pl=PLACE[d.id];
    row.setAttribute('data-loc',pl?pl.text:'');
    levels.forEach(function(x){var v=(pl&&pl.fields[x])||'';row.appendChild(h('td',{'class':'loc-td','data-level':x,text:v,title:(v&&labelOf(v)!==v)?labelOf(v):''}));});
    if(stateOn()){
      var stc=h('td',{class:'state'});
      if(STATES[d.id]){paintState(stc,STATES[d.id]);}
      row.appendChild(stc);
    }
    var acts=h('td');var res=h('td',{class:'result'});
    if(RES[d.id]){paintResult(res,RES[d.id]);}
    DOOR_ACTIONS.forEach(function(a){
      var def=CFG.actions[a];if(!isMapped(def)){return;}
      var btn=h('button',{class:'act','data-action':a,text:def.label||a});
      btn.onclick=function(){runAction(a,d,btn);};
      btn.disabled=licBlocked();btn.title=licTip();
      acts.appendChild(btn);
    });
    row.appendChild(acts);row.appendChild(res);body.appendChild(row);
  });
  updateBatchBar();
}
function runAction(a,d,btn){
  var def=CFG.actions[a];
  var p=(def.confirm===false)?Promise.resolve(true):confirmDialog((def.label||a)+' door "'+d.name+'" ('+d.id+')?');
  p.then(function(ok){
    if(!ok){return;}
    btn.disabled=true;setRowResult(d.id,'','working...');
    return api('POST','/api/v1/doors/action',{action:a,id:d.id,name:d.name,extra:d.extra||{}}).then(function(r){
      setRowResult(d.id,r.ok?'ok':'bad',r.ok?(r.transport==='socket'?('OK (socket) reply: '+(r.reply||'')+' request id '+r._rid):('OK (HTTP '+r.httpStatus+') request id '+r._rid)):('FAILED: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')'),r._rid);
      if(r.state!==undefined&&r.state!==null){setState(d.id,r.state,r.stateDetail);}
      else if(stateOn()){return refreshStates([d]);}
    }).catch(function(e){
      setRowResult(d.id,'bad','FAILED: '+errText(e),e.rid||'-');
    }).then(function(){btn.disabled=licBlocked();});
  });
}
/* State of the listed doors: one request, one socket session on the server. */
function refreshStates(doors){
  if(!stateOn()||!doors.length){return Promise.resolve();}
  $('btn-refresh-state').disabled=true;
  setMsg('doors-msg','Reading the state of '+doors.length+' door(s)...');
  return api('POST','/api/v1/doors/state',{doors:doors.map(slim)}).then(function(r){
    (r.states||[]).forEach(function(x){setState(x.id,x.state,x.detail);});
    setMsg('doors-msg','State of '+(r.states||[]).length+' door(s) read (request id '+r._rid+')','good');
  }).catch(function(e){
    doors.forEach(function(d){setState(d.id,'?',e.message);});
    setMsg('doors-msg','State not read: '+errText(e),'bad');
  }).then(function(){$('btn-refresh-state').disabled=false;});
}
/* One action on many doors: one request, one socket session on the server (the page waits for the whole batch). */
function runBatch(a,doors,question,opts,meta){
  if(!doors.length||BATCH_BUSY){return;}
  var names=doors.slice(0,5).map(function(d){return d.name;}).join(', ')+(doors.length>5?', ...':'');
  confirmDialog(question+' First '+Math.min(5,doors.length)+': '+names,opts).then(function(ok){
    if(!ok){return;}
    BATCH_BUSY=true;updateBatchBar();
    doors.forEach(function(d){setRowResult(d.id,'','working on '+doors.length+' doors...');});
    setMsg('doors-msg','Working on '+doors.length+' door(s)...');
    var req={action:a,doors:doors.map(slim)};
    if(meta&&meta.report){req.report=meta.report;}
    return api('POST','/api/v1/doors/batch',req).then(function(r){
      (r.results||[]).forEach(function(x){
        setRowResult(x.id,x.ok?'ok':'bad',x.ok?('OK (batch)'+(x.reply?(' reply: '+x.reply):'')+' request id '+r._rid):('FAILED: '+(x.fault||'no reply')+(x.refused?' (refused, not sent)':'')+' (request id '+r._rid+')'),r._rid);
        if(x.state!==undefined&&x.state!==null){setState(x.id,x.state,x.stateDetail);}
      });
      setMsg('doors-msg',r.okCount+' of '+r.count+' door(s) OK, '+r.failCount+' failed (request id '+r._rid+')',r.failCount?'bad':'good');
      if(meta){showReport(r,doors,a,meta);}
    }).catch(function(e){
      doors.forEach(function(d){setRowResult(d.id,'bad','FAILED: '+errText(e),e.rid||'-');});
      setMsg('doors-msg','Batch failed: '+errText(e),'bad');
    }).then(function(){BATCH_BUSY=false;updateBatchBar();});
  });
}
$('btn-refresh-state').onclick=function(){refreshStates(visibleDoors());};
$('btn-arm').onclick=function(){var ds=selectedDoors();armRun('arm',ds,selScope(ds));};
$('btn-disarm').onclick=function(){var ds=selectedDoors();armRun('disarm',ds,selScope(ds));};
$('loc-filter-clear').onclick=function(){LOCFILTER='';renderDoors();};
$('arm-close').onclick=function(){ARMREP=null;$('arm-report').style.display='none';updateBatchBar();};
$('arm-export').onclick=function(){
  if(!ARMREP||!ARMREP.file){return;}
  var f=ARMREP.file;
  download('/api/v1/arming/report?file='+encodeURIComponent(f),f).catch(function(e){setMsg('doors-msg','Export failed: '+e.message,'bad');});
};
$('arm-retry').onclick=function(){
  if(!ARMREP||!ARMREP.failed.length){return;}
  var set={};ARMREP.failed.forEach(function(id){set[id]=true;});
  var ds=DOORS.filter(function(d){return set[d.id];});
  var m=ARMREP.meta;
  var lab=m.reportLabel+' (retry)';
  runBatch(ARMREP.a,ds,m.kindLabel+' again: '+ds.length+' failed door(s) of '+m.scopeName+'?',{title:m.kindLabel+' - failed doors',ok:'Retry'},
    {report:{label:lab},kindLabel:m.kindLabel,scopeName:m.scopeName,reportLabel:lab,retry:true});
};
$('btn-lockdown').onclick=function(){
  var def=CFG.actions.lock;
  runBatch('lock',DOORS.slice(),'LOCKDOWN: '+((def&&def.label)||'lock')+' ALL '+DOORS.length+' door(s) in the list?',{danger:true,title:'Lockdown',ok:'Lock all doors'});
};
$('btn-load-doors').onclick=function(){
  setMsg('doors-msg','Loading...');
  api('GET','/api/v1/doors').then(function(r){
    DOORS=r.doors||[];SEL={};STATES={};RES={};LOCFILTER='';PAGE=1;ARMREP=null;$('arm-report').style.display='none';renderDoors();updateLocTest();loadLicense();
    if(r.ok){
      setMsg('doors-msg',DOORS.length+' door(s) loaded (request id '+r._rid+')','good');
      if(stateOn()&&DOORS.length){return refreshStates(visibleDoors());}
    }
    else{setMsg('doors-msg','AEOS answered with an error: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')','bad');}
  }).catch(function(e){DOORS=[];LOCFILTER='';renderDoors();setMsg('doors-msg',errText(e),'bad');});
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
    if(a!=='listDoors'){
      var tr=h('select',{id:'tr-'+a},[h('option',{value:'soap',text:'SOAP'}),h('option',{value:'socket',text:'Socket'})]);
      fs.appendChild(lbl('Transport',tr));
      fs.appendChild(lbl('Socket command ({{id}} {{name}} {{<extra column>}})',h('input',{type:'text',id:'cmd-'+a,size:'46'})));
      fs.appendChild(lbl('Success pattern (regex on the reply line; empty = any reply)',h('input',{type:'text',id:'sp-'+a,size:'20'})));
      fs.appendChild(h('br'));
    }
    var sel=h('select',{id:'op-'+a});
    sel.onchange=function(){var o=opByName(sel.value);if(o){$('sa-'+a).value=o.soapAction||'';}};
    fs.appendChild(lbl('WSDL operation',sel));
    fs.appendChild(lbl('SOAP action',h('input',{type:'text',id:'sa-'+a,size:'40'})));
    var sk=h('button',{id:'skel-'+a,text:'Insert skeleton'});
    sk.onclick=function(){var o=opByName($('op-'+a).value);if(o){$('body-'+a).value=o.skeleton;}else{setMsg('setup-msg','Select an operation (Load WSDL first) to insert its skeleton.','bad');}};
    fs.appendChild(sk);
    fs.appendChild(h('label',{style:'display:block'},[h('span',{text:a==='listDoors'?'Request body template ({{ns}} {{tns}} {{start}} {{pageSize}})':'Request body template ({{id}} {{name}} {{ns}} {{tns}})'}),h('textarea',{id:'body-'+a})]));
    if(a==='listDoors'){
      fs.appendChild(lbl('Door element',h('input',{type:'text',id:'itemElement',size:'18'})));
      fs.appendChild(lbl('Id field',h('input',{type:'text',id:'idField',size:'18'})));
      fs.appendChild(lbl('Name field',h('input',{type:'text',id:'nameField',size:'18'})));
      fs.appendChild(lbl('Extra columns (comma separated)',h('input',{type:'text',id:'extraFields',size:'28'})));
      fs.appendChild(lbl('Page size (0 = one request; paging needs {{start}} in the body)',h('input',{type:'number',id:'pageSize',min:'0',max:'100000',style:'width:7em'})));
    }
    box.appendChild(fs);
  });
}
function buildDoorStateSetup(){
  var box=$('setup-doorstate');box.innerHTML='';
  var fs=h('fieldset',{id:'fs-doorState'},[h('legend',{text:'Door state (socket interface; shown as the State column)'})]);
  fs.appendChild(h('p',{style:'margin:4px 0;font-size:12px;color:#52606f',text:'Each check sends its command; the state is the label of the first check whose reply matches. Empty rows are ignored. Placeholders as in the action commands.'}));
  for(var i=1;i<=DS_ROWS;i++){
    fs.appendChild(lbl('Check '+i+' label',h('input',{type:'text',id:'ds-label-'+i,size:'12'})));
    fs.appendChild(lbl('Command',h('input',{type:'text',id:'ds-cmd-'+i,size:'46'})));
    fs.appendChild(lbl('Match pattern (regex on the reply line)',h('input',{type:'text',id:'ds-match-'+i,size:'22'})));
    fs.appendChild(h('br'));
  }
  fs.appendChild(lbl('Label when no check matches',h('input',{type:'text',id:'ds-otherwise',size:'16'})));
  fs.appendChild(lbl('Doors per socket session (more doors are split into several sessions)',h('input',{type:'number',id:'ds-max',min:'1',max:'5000',style:'width:90px'})));
  box.appendChild(fs);
}
/* ---- Setup: locations, door groups, arming ---- */
function splitLines(t){return String(t||'').replace(/\r/g,'').split('\n').map(function(x){return x.trim();}).filter(function(x){return x;});}
function readLocations(){
  var levels=$('loc-levels').value.split(',').map(function(x){return x.trim();}).filter(function(x){return x;});
  var rules=[];
  splitLines($('loc-rules').value).forEach(function(line){
    var m=/^(\S+)\s+(.+)$/.exec(line);
    rules.push(m?{source:m[1],pattern:m[2].trim()}:{source:line,pattern:''});
  });
  var map={},first=true;
  splitLines($('loc-map').value).forEach(function(line){
    var cells=line.split(/[;\t]/).map(function(x){return x.trim();});
    if(first){first=false;if(cells[0].toLowerCase()==='key'){return;}}
    if(!cells[0]){return;}
    var ent={};
    for(var i=1;i<cells.length&&i<=levels.length;i++){if(cells[i]){ent[levels[i-1]]=cells[i];}}
    map[cells[0]]=ent;
  });
  var labels={};
  splitLines($('loc-labels').value).forEach(function(line){
    var i=line.indexOf('=');if(i<1){return;}
    var k=line.slice(0,i).trim(),v=line.slice(i+1).trim();
    if(k&&v){labels[k]=v;}
  });
  return {levels:levels,rules:rules,map:map,labels:labels};
}
function fillLocations(){
  var l=CFG.locations||{};
  var levels=l.levels||[];
  $('loc-levels').value=levels.join(', ');
  $('loc-rules').value=(l.rules||[]).map(function(r){return r.source+' '+r.pattern;}).join('\n');
  $('loc-map').value=Object.keys(l.map||{}).map(function(k){
    var e=l.map[k]||{};return [k].concat(levels.map(function(lv){return e[lv]||'';})).join(';');
  }).join('\n');
  $('loc-labels').value=Object.keys(l.labels||{}).map(function(k){return k+'='+l.labels[k];}).join('\n');
  var a=CFG.arming||{};
  $('arm-action').value=a.armAction||'lock';$('arm-label').value=a.armLabel||'Arm';
  $('disarm-action').value=a.disarmAction||'normal';$('disarm-label').value=a.disarmLabel||'Disarm';
  var rows=$('grp-rows');rows.innerHTML='';
  (CFG.groups||[]).forEach(addGroupRow);
  updateLocTest();
}
function matchText(m){
  return Object.keys(m||{}).map(function(k){return k+'='+[].concat(m[k]).join(',');}).join('; ');
}
function parseMatch(t){
  var m={};
  String(t||'').split(';').forEach(function(part){
    var i=part.indexOf('=');if(i<1){return;}
    var k=part.slice(0,i).trim();
    var vals=part.slice(i+1).split(',').map(function(x){return x.trim();}).filter(function(x){return x;});
    if(k&&vals.length){m[k]=vals;}
  });
  return m;
}
function addGroupRow(g){
  g=g||{};
  var row=h('div',{'class':'grp-edit'});
  var cnt=h('span',{'class':'grp-matches'});
  var nm=h('input',{type:'text','class':'grp-name',size:'18'});nm.value=g.name||'';
  var mt=h('input',{type:'text','class':'grp-match',size:'40',placeholder:'city=BRU,ZAG; building=B1'});mt.value=matchText(g.match);
  var ids=h('input',{type:'text','class':'grp-ids',size:'26'});ids.value=[].concat(g.doorIds||[]).join(', ');
  var del=h('button',{'class':'grp-del',type:'button',text:'Remove'});
  del.onclick=function(){row.parentNode.removeChild(row);};
  [nm,mt,ids].forEach(function(el){el.oninput=updateGroupCounts;});
  row.appendChild(lbl('Group name',nm));
  row.appendChild(lbl('Locations: level=value,value; level=value',mt));
  row.appendChild(lbl('Door ids (comma separated)',ids));
  row.appendChild(cnt);row.appendChild(del);
  $('grp-rows').appendChild(row);
  updateGroupCounts();
}
function readGroups(){
  var out=[];
  Array.prototype.forEach.call(document.querySelectorAll('#grp-rows .grp-edit'),function(row){
    var name=row.querySelector('.grp-name').value.trim();
    var match=parseMatch(row.querySelector('.grp-match').value);
    var ids=row.querySelector('.grp-ids').value.split(',').map(function(x){return x.trim();}).filter(function(x){return x;});
    if(name||Object.keys(match).length||ids.length){out.push({name:name,match:match,doorIds:ids});}
  });
  return out;
}
function updateGroupCounts(){
  if(!$('loc-levels')){return;}
  var loc=readLocations();
  var rows=document.querySelectorAll('#grp-rows .grp-edit');
  Array.prototype.forEach.call(rows,function(row){
    var g={name:'',match:parseMatch(row.querySelector('.grp-match').value),
      doorIds:row.querySelector('.grp-ids').value.split(',').map(function(x){return x.trim();}).filter(function(x){return x;})};
    var c=row.querySelector('.grp-matches');
    if(!DOORS.length){c.textContent='Load the doors (Doors tab) to count the matches.';return;}
    var n=DOORS.filter(function(d){return doorInGroup(d,placeDoor(d,loc),g);}).length;
    c.textContent='matches '+n+' door'+(n===1?'':'s');
  });
}
function updateLocTest(){
  if(!$('loc-levels')){return;}
  var loc=readLocations();
  var t=$('loc-test-input').value;
  var out=$('loc-test-out');out.innerHTML='';
  function line(x){out.appendChild(h('div',{text:x}));}
  if(!t){line('Type a controller or door name above to see how the rules read it.');}
  else{
    var won=false;
    loc.rules.forEach(function(r,i){
      var re=null;try{re=new RegExp(r.pattern);}catch(e){line('Rule '+(i+1)+': not a valid pattern ('+e.message+')');return;}
      var m=re.exec(t);
      if(!m){line('Rule '+(i+1)+' ('+r.source+'): no match');return;}
      var g=m.groups||{};
      var parts=Object.keys(g).filter(function(k){return g[k];}).map(function(k){return k+'='+g[k];});
      line('Rule '+(i+1)+' ('+r.source+') matches: '+(parts.join(', ')||'(no named group has a value)')+(won?' - not used, an earlier rule won':''));
      won=true;
    });
    if(!loc.rules.length){line('No rules yet.');}
    var ex={};loc.rules.forEach(function(r){ex[r.source]=t;});
    var pl=placeDoor({id:t,name:t,extra:ex},loc);
    var res=h('div',{id:'loc-test-result',text:'Placed at: '+(pl.placed?pl.path.map(labelOfIn(loc)).join(' / '):'(unplaced)')});
    out.appendChild(res);
  }
  var rc=$('loc-rule-counts');
  if(!DOORS.length){rc.textContent='Load the doors (Doors tab) to see how many doors each rule places.';}
  else{
    var n=loc.rules.map(function(){return 0;}),mapOnly=0,un=0;
    DOORS.forEach(function(d){
      var pl2=placeDoor(d,loc);
      if(pl2.rule>0){n[pl2.rule-1]++;}else if(pl2.placed){mapOnly++;}
      if(!pl2.placed){un++;}
    });
    var parts2=loc.rules.map(function(r,i){return 'Rule '+(i+1)+' places '+n[i]+' of '+DOORS.length+' listed doors.';});
    if(mapOnly){parts2.push('Placed by the map only: '+mapOnly+'.');}
    parts2.push('Not placed: '+un+'.');
    rc.textContent=parts2.join(' ');
  }
  updateGroupCounts();
}
function labelOfIn(loc){return function(v){return (loc.labels&&hasOwn(loc.labels,v)&&loc.labels[v])?loc.labels[v]:v;};}
function buildLocationSetup(){
  var box=$('setup-locations');box.innerHTML='';
  var fl=h('fieldset',{id:'fs-locations'},[h('legend',{text:'Locations (read from the controller or door names)'})]);
  fl.appendChild(h('p',{'class':'hint',text:'Controller names often hold the place. A rule reads one source (name, id, or an extra column such as HostName) with a regular expression; every named group becomes a field, for example (?<city>[A-Z]{3}). The first rule that matches wins. The map overrides the rules for names that do not follow the scheme. Leave the levels empty to switch locations off.'}));
  fl.appendChild(lbl('Levels in order, comma separated (for example country, city, site, building, floor)',h('input',{type:'text',id:'loc-levels',size:'70'})));
  fl.appendChild(h('label',{style:'display:block'},[h('span',{text:'Rules, one per line: <source> <pattern>'}),h('textarea',{id:'loc-rules',style:'min-height:60px'})]));
  fl.appendChild(h('label',{style:'display:block'},[h('span',{text:'Map, one per line: key;level 1 value;level 2 value;... (key = door id, door name or an extra column value such as the controller name; the columns follow the levels above)'}),h('textarea',{id:'loc-map',style:'min-height:60px'})]));
  var mf=h('input',{type:'file',id:'loc-map-file',accept:'.csv,.txt,text/csv,text/plain'});
  mf.onchange=function(){
    var f=mf.files&&mf.files[0];if(!f){return;}
    var rd=new FileReader();
    rd.onload=function(){
      $('loc-map').value=String(rd.result||'').replace(/\r/g,'');updateLocTest();
      setMsg('setup-msg','Map imported from '+f.name+' ('+splitLines($('loc-map').value).length+' line(s)). Press Save to keep it.','good');
    };
    rd.readAsText(f);
  };
  fl.appendChild(h('p',null,[h('label',null,[h('span',{text:'Import the map from a CSV file (separator ;)'}),mf])]));
  fl.appendChild(h('label',{style:'display:block'},[h('span',{text:'Labels, one per line: value=display name (for example BRU=Brussels)'}),h('textarea',{id:'loc-labels',style:'min-height:44px'})]));
  fl.appendChild(lbl('Tester: type a controller or door name',h('input',{type:'text',id:'loc-test-input',size:'40'})));
  fl.appendChild(h('div',{id:'loc-test-out','class':'loc-out'}));
  fl.appendChild(h('div',{id:'loc-rule-counts','class':'hint'}));
  ['loc-levels','loc-rules','loc-map','loc-labels','loc-test-input'].forEach(function(id){fl.querySelector('#'+id).oninput=updateLocTest;});
  box.appendChild(fl);
  var fa=h('fieldset',{id:'fs-arming'},[h('legend',{text:'Arm / Disarm'})]);
  fa.appendChild(h('p',{'class':'hint',text:'Arm and Disarm are two of the door actions above, run on many doors at once. Arm is normally Lock and Disarm is normally Normal.'}));
  function actSel(id){return h('select',{id:id},DOOR_ACTIONS.map(function(a){return h('option',{value:a,text:a});}));}
  fa.appendChild(lbl('Arm runs the action',actSel('arm-action')));
  fa.appendChild(lbl('Arm button label',h('input',{type:'text',id:'arm-label',size:'14'})));
  fa.appendChild(lbl('Disarm runs the action',actSel('disarm-action')));
  fa.appendChild(lbl('Disarm button label',h('input',{type:'text',id:'disarm-label',size:'14'})));
  box.appendChild(fa);
  var fg=h('fieldset',{id:'fs-groups'},[h('legend',{text:'Door groups'})]);
  fg.appendChild(h('p',{'class':'hint',text:'A group is a location filter (every listed level must match, any of its values) and / or a list of door ids. A new door on that floor joins the group by itself.'}));
  fg.appendChild(h('div',{id:'grp-rows'}));
  var add=h('button',{id:'grp-add',type:'button',text:'Add group'});
  add.onclick=function(){addGroupRow({});};
  fg.appendChild(add);
  box.appendChild(fg);
}
function fillSetup(){
  $('cfg-aeosUrl').value=CFG.aeosUrl;$('cfg-wsdlUrl').value=CFG.wsdlUrl;$('cfg-soapVersion').value=CFG.soapVersion;
  $('cfg-auth').value=CFG.auth;$('cfg-timeoutSec').value=CFG.timeoutSec;$('cfg-namespacePrefix').value=CFG.namespacePrefix;
  $('cfg-targetNamespace').value=CFG.targetNamespace;$('cfg-tlsSkipValidation').checked=!!CFG.tlsSkipValidation;
  $('cfg-auditFile').value=CFG.auditFile;$('cfg-debugLogFile').value=CFG.debugLogFile;$('cfg-debugLevel').value=CFG.debugLevel;
  ACTIONS.forEach(function(a){
    var o=CFG.actions[a];fillOps($('op-'+a),o.operation);$('sa-'+a).value=o.soapAction;$('body-'+a).value=o.body;
    if(a!=='listDoors'){$('lbl-'+a).value=o.label;$('conf-'+a).checked=(o.confirm!==false);$('tr-'+a).value=o.transport||'soap';$('cmd-'+a).value=o.command||'';$('sp-'+a).value=o.successPattern||'';}
  });
  var k=CFG.socket;
  $('sk-host').value=k.host;$('sk-port').value=k.port;$('sk-terminator').value=k.terminator;$('sk-greetingWaitMs').value=k.greetingWaitMs;
  $('sk-replyTimeoutSec').value=k.replyTimeoutSec;$('sk-tls').checked=(k.tls!==false);$('sk-tlsSkipValidation').checked=!!k.tlsSkipValidation;
  $('sk-loginTemplate').value=k.loginTemplate;$('sk-loginSuccessPattern').value=k.loginSuccessPattern;$('sk-initCommands').value=(k.initCommands||[]).join('\n');
  var ds=CFG.doorState||{};var dc=ds.checks||[];
  for(var i=1;i<=DS_ROWS;i++){var c=dc[i-1]||{};$('ds-label-'+i).value=c.label||'';$('ds-cmd-'+i).value=c.command||'';$('ds-match-'+i).value=c.matchPattern||'';}
  $('ds-otherwise').value=ds.otherwiseLabel||'';$('ds-max').value=ds.maxDoorsPerRefresh||500;
  var l=CFG.actions.listDoors;$('itemElement').value=l.itemElement;$('idField').value=l.idField;$('nameField').value=l.nameField;
  $('extraFields').value=(l.extraFields||[]).join(', ');$('pageSize').value=l.pageSize||0;
  fillLocations();
}
function readSetup(){
  var c=JSON.parse(JSON.stringify(CFG));
  c.aeosUrl=$('cfg-aeosUrl').value.trim();c.wsdlUrl=$('cfg-wsdlUrl').value.trim();c.soapVersion=$('cfg-soapVersion').value;
  c.auth=$('cfg-auth').value;c.timeoutSec=parseInt($('cfg-timeoutSec').value,10)||30;c.namespacePrefix=$('cfg-namespacePrefix').value.trim();
  c.targetNamespace=$('cfg-targetNamespace').value.trim();c.tlsSkipValidation=$('cfg-tlsSkipValidation').checked;
  c.auditFile=$('cfg-auditFile').value.trim();c.debugLogFile=$('cfg-debugLogFile').value.trim();c.debugLevel=$('cfg-debugLevel').value;
  ACTIONS.forEach(function(a){
    var o=c.actions[a];o.operation=$('op-'+a).value;o.soapAction=$('sa-'+a).value;o.body=$('body-'+a).value;
    if(a!=='listDoors'){o.label=$('lbl-'+a).value;o.confirm=$('conf-'+a).checked;o.transport=$('tr-'+a).value;o.command=$('cmd-'+a).value;o.successPattern=$('sp-'+a).value;}
  });
  var k=c.socket;
  k.host=$('sk-host').value.trim();k.port=parseInt($('sk-port').value,10)||0;k.terminator=$('sk-terminator').value;
  k.greetingWaitMs=parseInt($('sk-greetingWaitMs').value,10);if(isNaN(k.greetingWaitMs)){k.greetingWaitMs=2000;}
  k.replyTimeoutSec=parseInt($('sk-replyTimeoutSec').value,10)||10;k.tls=$('sk-tls').checked;k.tlsSkipValidation=$('sk-tlsSkipValidation').checked;
  k.loginTemplate=$('sk-loginTemplate').value.trim();k.loginSuccessPattern=$('sk-loginSuccessPattern').value.trim();
  k.initCommands=$('sk-initCommands').value.split('\n').map(function(x){return x.trim();}).filter(function(x){return x;});
  var dchecks=[];
  for(var i=1;i<=DS_ROWS;i++){
    var dl=$('ds-label-'+i).value.trim(),dm=$('ds-cmd-'+i).value.trim(),dp=$('ds-match-'+i).value.trim();
    if(dl||dm||dp){dchecks.push({label:dl,command:dm,matchPattern:dp});}
  }
  c.doorState={checks:dchecks,otherwiseLabel:$('ds-otherwise').value.trim(),maxDoorsPerRefresh:parseInt($('ds-max').value,10)||500};
  var l=c.actions.listDoors;l.itemElement=$('itemElement').value.trim();l.idField=$('idField').value.trim();l.nameField=$('nameField').value.trim();
  l.extraFields=$('extraFields').value.split(',').map(function(s){return s.trim();}).filter(function(s){return s;});
  l.pageSize=parseInt($('pageSize').value,10)||0;
  c.locations=readLocations();
  c.groups=readGroups();
  c.arming={armAction:$('arm-action').value,disarmAction:$('disarm-action').value,armLabel:$('arm-label').value.trim(),disarmLabel:$('disarm-label').value.trim()};
  return c;
}
/* Save what is on the Setup tab, then reload it from the server (header, banners, doors follow). */
function saveSetup(){
  return api('PUT','/api/v1/config',readSetup()).then(function(r){
    return api('GET','/api/v1/config').then(function(c){CFG=c;fillSetup();renderBanners();renderDoors();return loadLicense().then(function(){return r;});});
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
    if(r.ok){setMsg('setup-msg','Parsed '+(r.doors||[]).length+' door(s) in '+(r.pages||1)+' page(s) (request id '+r._rid+')','good');}
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

$('btn-raw-socket-send').onclick=function(){
  setMsg('raw-socket-msg','Sending...');$('raw-socket-out').textContent='';
  api('POST','/api/v1/socket',{command:$('raw-socket-cmd').value}).then(function(r){
    $('raw-socket-out').textContent=(r.transcript||[]).join('\n');
    if(r.ok){setMsg('raw-socket-msg','OK, reply: '+(r.reply||'')+' (request id '+r._rid+')','good');}
    else{setMsg('raw-socket-msg','Failed: '+(r.fault||'no reply')+' (request id '+r._rid+')','bad');}
  }).catch(function(e){setMsg('raw-socket-msg',errText(e),'bad');});
};

/* ---- audit ---- */
function loadAudit(){
  api('GET','/api/v1/audit?limit=50').then(function(r){
    var b=$('audit-body');b.innerHTML='';
    (r.records||[]).slice().reverse().forEach(function(x){
      b.appendChild(h('tr',null,[h('td',{text:x.ts}),h('td',{text:x.windowsUser}),h('td',{text:x.aeosUser}),h('td',{text:x.action+(x.batch?(' ['+x.batch+']'):'')}),
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
  download('/api/v1/debuglog/download','doorkeeper-debug.log').catch(function(e){setMsg('debug-msg','Download failed: '+e.message,'bad');});
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
buildDoorStateSetup();
buildLocationSetup();
api('GET','/api/v1/config').then(function(c){
  CFG=c;fillSetup();renderBanners();renderDoors();
  return loadLicense().then(function(){return api('GET','/api/v1/session');});
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
    if (-not $ConfigFile) {
        $script:ConfigPath = Join-Path $script:ScriptDir 'doorkeeper.json'
        $oldCfg = Join-Path $script:ScriptDir 'aeos-console.json'
        if (-not (Test-Path -LiteralPath $script:ConfigPath) -and (Test-Path -LiteralPath $oldCfg)) { $script:ConfigPath = $oldCfg }
    }
    else { $script:ConfigPath = [System.IO.Path]::GetFullPath($ConfigFile) }
    $script:Port = $Port
    $script:Cred = $null
    $script:DataDir = Split-Path -Parent $script:ConfigPath
    if ($LicenseFile) { $script:LicensePath = [System.IO.Path]::GetFullPath($LicenseFile) }
    else { $script:LicensePath = Join-Path $script:DataDir 'license.json' }
    $script:LastDoorCount = 0
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
    Write-Host ('DoorKeeper ' + $script:Version + ' listening on ' + $url + '  (Ctrl+C stops it)')
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
