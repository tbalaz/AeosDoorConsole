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

.PARAMETER InternalPort
    Only with -BehindProxy. The port DoorKeeper's own listener (HttpListener, HTTP.sys) binds on http://localhost:<InternalPort>/
    (default 8765). -Port is then the port IIS HttpPlatformHandler gives the child (%HTTP_PLATFORM_PORT%): DoorKeeper binds it with a
    plain TCP relay on 127.0.0.1 that copies every connection to the internal listener (HttpPlatformHandler cannot start a child
    that listens through HTTP.sys). The URL Rewrite rule of the sample web.config sets the Host header to localhost:<InternalPort>.

.PARAMETER BehindProxy
    Run behind a reverse proxy (IIS HttpPlatformHandler): session cookie is Secure, the Origin must equal -PublicUrl, the
    forwarded client address (X-DK-Client-IP, set by the URL Rewrite rule) is read on requests from 127.0.0.1 only, and an empty admin list gives
    nobody admin rights (the first admin is set in the config file on the server).

.PARAMETER PublicUrl
    The address operators use, for example https://doorkeeper.example.org . Required with -BehindProxy.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\DoorKeeper.ps1
    powershell -ExecutionPolicy Bypass -File .\DoorKeeper.ps1 -Port 9000 -NoBrowser
    powershell -NoProfile -ExecutionPolicy Bypass -File .\DoorKeeper.ps1 -Port %HTTP_PLATFORM_PORT% -InternalPort 8765 -NoBrowser -BehindProxy -PublicUrl https://doorkeeper.example.org
#>
[CmdletBinding()]
param(
    [string]$ConfigFile = '',
    [string]$LicenseFile = '',
    [int]$Port = 8765,
    [int]$InternalPort = 8765,
    [switch]$NoBrowser,
    [switch]$BehindProxy,
    [string]$PublicUrl = ''
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
$script:SelfPath = $PSCommandPath
$script:BehindProxy = [bool]$BehindProxy
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
    # v1: SHA256(prevHash|ts|windowsUser|aeosUser|action|doorId|doorName|httpStatus|ok[|batch]), hex, UTF-8.
    # The batch part is added only when the record has one, so records from before batches keep their hash.
    # v2 (records with "v":2): the same nine parts, then v2|batch|computer|doorAlias (batch may be empty). The version
    # marker and the computer / alias are covered, so a v2 line cannot be passed off as v1 or have them edited.
    # v3 (records with "v":3): the v2 parts, with the marker v3, then the client address (clientIp, as IIS forwarded it).
    param([string]$PrevHash, [string]$Ts, [string]$WindowsUser, [string]$AeosUser, [string]$Action,
        [string]$DoorId, [string]$DoorName, [int]$HttpStatus, [bool]$Ok, [string]$Batch = '',
        [int]$Version = 1, [string]$Computer = '', [string]$DoorAlias = '', [string]$ClientIp = '', [string]$Fault = '')
    $okText = 'false'
    if ($Ok) { $okText = 'true' }
    $parts = @($PrevHash, $Ts, $WindowsUser, $AeosUser, $Action, $DoorId, $DoorName, [string]$HttpStatus, $okText)
    if ($Version -ge 4) {
        # v4: EVERY field (the fault text too) in one JSON text of an ordered field list - no separator can be faked.
        $o = [ordered]@{ v = 4; prev = $PrevHash; ts = $Ts; windowsUser = $WindowsUser; aeosUser = $AeosUser; action = $Action; doorId = $DoorId; doorName = $DoorName
            httpStatus = [int]$HttpStatus; ok = [bool]$Ok; fault = [string]$Fault; batch = $Batch; computer = $Computer; doorAlias = $DoorAlias; clientIp = $ClientIp }
        $s4 = ConvertTo-Json -InputObject $o -Compress
        $sha4 = [System.Security.Cryptography.SHA256]::Create()
        try { $b4 = $sha4.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($s4)) } finally { $sha4.Dispose() }
        return (($b4 | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    if ($Version -ge 3) { $parts += @('v3', $Batch, $Computer, $DoorAlias, $ClientIp) }
    elseif ($Version -ge 2) { $parts += @('v2', $Batch, $Computer, $DoorAlias) }
    elseif ($Batch) { $parts += $Batch }
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
        $ver = 1
        if ($r.PSObject.Properties['v'] -and [int]$r.v -ge 4) { $ver = 4 }
        elseif ($r.PSObject.Properties['v'] -and [int]$r.v -ge 3) { $ver = 3 }
        elseif ($r.PSObject.Properties['v'] -and [int]$r.v -ge 2) { $ver = 2 }
        $h = Get-AuditHash -PrevHash $prev -Ts ([string]$r.ts) -WindowsUser ([string]$r.windowsUser) -AeosUser ([string]$r.aeosUser) `
            -Action ([string]$r.action) -DoorId ([string]$r.doorId) -DoorName ([string]$r.doorName) `
            -HttpStatus ([int]$r.httpStatus) -Ok ([bool]$r.ok) -Batch ([string]$r.batch) `
            -Version $ver -Computer ([string]$r.computer) -DoorAlias ([string]$r.doorAlias) -ClientIp ([string]$r.clientIp) -Fault ([string]$r.fault)
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
    "maxDoorsPerRefresh": 500,
    "pollSeconds": 30,
    "freshSeconds": 120
  },
  "locations": { "levels": [], "rules": [], "map": {}, "labels": {} },
  "groups": [],
  "arming": { "armAction": "lock", "disarmAction": "normal", "armLabel": "Arm", "disarmLabel": "Disarm" },
  "access": { "admins": [], "idleMinutes": 15 },
  "aliases": {}
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
        $pw = 0
        if (-not [int]::TryParse([string]$ds.pollSeconds, [ref]$pw) -or $pw -lt 1 -or $pw -gt 3600) { $errs.Add('doorState.pollSeconds must be a number from 1 to 3600.') }
        $fw = 0
        if (-not [int]::TryParse([string]$ds.freshSeconds, [ref]$fw) -or $fw -lt 5 -or $fw -gt 86400) { $errs.Add('doorState.freshSeconds must be a number from 5 to 86400.') }
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
    $ac = $Config.access
    if ($null -ne $ac) {
        $im = 0
        if (-not [int]::TryParse([string]$ac.idleMinutes, [ref]$im) -or $im -lt 1 -or $im -gt 720) { $errs.Add('access.idleMinutes must be a number from 1 to 720.') }
        $seenAd = @{}
        foreach ($an in @($ac.admins)) {
            $n = ([string]$an).Trim()
            if (-not $n) { $errs.Add('access.admins must not hold an empty name.'); continue }
            if ($n.Length -gt 200 -or $n -match '[\x00-\x1F\x7F]') { $errs.Add('access.admins: a name is too long or has a control character.'); continue }
            if ($seenAd.ContainsKey($n.ToLowerInvariant())) { $errs.Add('access.admins: the name "' + $n + '" is listed twice.'); continue }
            $seenAd[$n.ToLowerInvariant()] = $true
        }
    }
    if ($null -ne $Config.aliases) {
        if ($Config.aliases -isnot [System.Management.Automation.PSCustomObject]) { $errs.Add('aliases must be an object of door id -> friendly name.') }
        else {
            foreach ($ap in $Config.aliases.PSObject.Properties) {
                $ae = Test-AliasEntry -Id $ap.Name -Alias $ap.Value
                if ($ae) { $errs.Add($ae) }
            }
        }
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
# Operators and admins, aliases, per-user settings, audit filter, last-known states (pure helpers first)
# ============================================================================

function Test-AliasEntry {
    # One door id -> friendly name pair. Returns a problem text, or $null when it is fine.
    param($Id, $Alias)
    $k = [string]$Id
    if (-not $k -or $k.Length -gt 200 -or $k -match '[\x00-\x1F\x7F]') { return 'aliases: a door id is empty, longer than 200 characters or has a control character.' }
    if ($Alias -isnot [string]) { return ('aliases["' + $k + '"] must be text.') }
    if (-not $Alias.Trim()) { return ('aliases["' + $k + '"] must not be empty (remove the entry instead).') }
    if ($Alias.Length -gt 200) { return ('aliases["' + $k + '"] is longer than 200 characters.') }
    if ($Alias -match '[\x00-\x1F\x7F]') { return ('aliases["' + $k + '"] has a control character.') }
    return $null
}

function Get-DoorAlias {
    param([string]$Id)
    if (-not $Id -or $null -eq $script:Config) { return '' }
    $al = $script:Config.PSObject.Properties['aliases']
    if (-not $al -or $null -eq $al.Value) { return '' }
    $p = $al.Value.PSObject.Properties[$Id]
    if ($p) { return [string]$p.Value }
    return ''
}

function Get-AeosTargetChanges {
    # The reasons (field names) why a new config points the server account somewhere else or makes its transport weaker:
    # aeosUrl, socket.host, socket.port, socket.tls (true -> false), tlsSkipValidation and socket.tlsSkipValidation (false -> true).
    param($Old, $New)
    $why = @()
    if ($null -eq $Old -or $null -eq $New) { return @($why) }
    if ([string]$Old.aeosUrl -ne [string]$New.aeosUrl) { $why += 'aeosUrl' }
    if ($null -ne $Old.socket -and $null -ne $New.socket) {
        if ([string]$Old.socket.host -ne [string]$New.socket.host) { $why += 'socket.host' }
        if ([string]$Old.socket.port -ne [string]$New.socket.port) { $why += 'socket.port' }
        if ($Old.socket.tls -ne $false -and $New.socket.tls -eq $false) { $why += 'socket.tls' }
        if ($Old.socket.tlsSkipValidation -ne $true -and $New.socket.tlsSkipValidation -eq $true) { $why += 'socket.tlsSkipValidation' }
    }
    if ($Old.tlsSkipValidation -ne $true -and $New.tlsSkipValidation -eq $true) { $why += 'tlsSkipValidation' }
    return @($why)
}

function Get-AdminList {
    # The admin names of the config, trimmed, without empty entries.
    $list = @()
    if ($null -ne $script:Config -and $null -ne $script:Config.PSObject.Properties['access'] -and $null -ne $script:Config.access) {
        foreach ($a in @($script:Config.access.admins)) { if ($null -ne $a -and ([string]$a).Trim()) { $list += ([string]$a).Trim() } }
    }
    return @($list)
}

function Get-UserRole {
    # admin = the name is in the admin list (case-insensitive). Everybody else, and a visitor who is not logged in when
    # admins are set, is an operator. An EMPTY list is the first run: without -BehindProxy every user is an admin (even
    # one who is not logged in); with -BehindProxy nobody is (the first admin is set in the config file on the server).
    param([string[]]$Admins, [string]$User, [switch]$BehindProxy)
    $list = @($Admins | Where-Object { $null -ne $_ -and ([string]$_).Trim() })
    if ($list.Count -eq 0) { if ($BehindProxy) { return 'operator' } else { return 'admin' } }
    $u = ([string]$User).Trim()
    if ($u) { foreach ($a in $list) { if ([string]::Equals(([string]$a).Trim(), $u, [System.StringComparison]::OrdinalIgnoreCase)) { return 'admin' } } }
    return 'operator'
}

function Get-CurrentUserName {
    if ($null -ne $script:Cred) { return [string]$script:Cred.UserName }
    return ''
}

function Get-SessionInfo {
    $u = Get-CurrentUserName
    $admins = @(Get-AdminList)
    $role = Get-UserRole -Admins $admins -User $u -BehindProxy:([bool]$script:BehindProxy)
    $info = @{ loggedIn = ($null -ne $script:Cred); user = $u; role = $role; noAdmins = ($admins.Count -eq 0); behindProxy = [bool]$script:BehindProxy; csrf = '' }
    if ($null -ne $script:Sess) { $info.csrf = [string]$script:Sess.Csrf }
    elseif (-not $script:BehindProxy) { $info.csrf = [string]$script:Token }
    return $info
}

function Assert-Admin {
    $u = Get-CurrentUserName
    if ((Get-UserRole -Admins @(Get-AdminList) -User $u -BehindProxy:([bool]$script:BehindProxy)) -ne 'admin') {
        throw (New-ApiException 403 'forbidden_role' 'Only an admin can do this. Ask an admin of this console (Setup tab, Admins).')
    }
}

function Test-AdminOnlyRoute {
    # Routes an operator must not use. Door list, state, actions, batch, arming, license read, session and own settings stay open.
    param([string]$Method, [string]$Path)
    $k = $Method.ToUpperInvariant() + ' ' + $Path
    # Ignore letter case like the route match does (-eq / switch): 'PUT /api/v1/Aliases' must not skip the check.
    if ($k.StartsWith('PUT /api/v1/aliases', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    # The server account: every method (read, set, remove) is admin only.
    if ($Path.Equals('/api/v1/server-account', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $admin = @('PUT /api/v1/config', 'GET /api/v1/wsdl', 'PUT /api/v1/license', 'POST /api/v1/call', 'POST /api/v1/socket',
        'GET /api/v1/audit', 'GET /api/v1/audit/export', 'GET /api/v1/debuglog', 'GET /api/v1/debuglog/download',
        'POST /api/v1/diagnostics', 'GET /api/v1/diagnostics/download')
    return ($admin -contains $k)
}
function Test-AdminListChange {
    # The admin who saves must stay an admin: the list cannot be emptied (that would make every user an admin) and
    # must keep his own name. While the list is empty the first save needs a logged-in user who puts his own name in.
    param([string[]]$Old, [string[]]$New, [string]$User)
    $o = @($Old | Where-Object { $null -ne $_ -and ([string]$_).Trim() })
    $n = @($New | Where-Object { $null -ne $_ -and ([string]$_).Trim() })
    if ($n.Count -eq 0) {
        if ($o.Count -gt 0) { return 'The admin list cannot be emptied: every user would become an admin. Keep your own name in it.' }
        return $null
    }
    $u = ([string]$User).Trim()
    if (-not $u) { return 'Log in first: the admin list must hold your own AEOS user name, otherwise you could not change settings any more.' }
    foreach ($a in $n) { if ([string]::Equals(([string]$a).Trim(), $u, [System.StringComparison]::OrdinalIgnoreCase)) { return $null } }
    return ('The admin list must keep your own name (' + $u + '). Another admin can remove it.')
}

function ConvertTo-UserSettings {
    # Per-user page settings: rows per page, sort column + direction, last filter text, selected tree node.
    # Missing fields get defaults; a wrong type or a too long text is refused. Returns @{ ok; error; value }.
    param($In)
    $res = @{ ok = $false; error = ''; value = $null }
    if ($null -eq $In -or $In -isnot [System.Management.Automation.PSCustomObject]) { $res.error = 'The settings must be a JSON object.'; return $res }
    $rows = 100
    $sortCol = ''
    $sortDir = ''
    $filter = ''
    $node = ''
    $p = $In.PSObject.Properties['rows']
    if ($p -and $null -ne $p.Value) {
        $v = 0
        if (-not [int]::TryParse([string]$p.Value, [ref]$v) -or @(0, 25, 50, 100, 250, 500) -notcontains $v) { $res.error = 'rows must be 25, 50, 100, 250, 500 or 0 (all).'; return $res }
        $rows = $v
    }
    $caps = @{ sortCol = 100; filter = 200; node = 400 }
    foreach ($k in @('sortCol', 'sortDir', 'filter', 'node')) {
        $q = $In.PSObject.Properties[$k]
        if (-not $q -or $null -eq $q.Value) { continue }
        if ($q.Value -isnot [string]) { $res.error = $k + ' must be text.'; return $res }
        $t = [string]$q.Value
        if ($t -match '[\x00-\x1F\x7F]') { $res.error = $k + ' has a control character.'; return $res }
        if ($caps.ContainsKey($k) -and $t.Length -gt $caps[$k]) { $res.error = $k + ' is longer than ' + $caps[$k] + ' characters.'; return $res }
        if ($k -eq 'sortCol') { $sortCol = $t }
        elseif ($k -eq 'sortDir') {
            if (@('', 'asc', 'desc') -notcontains $t) { $res.error = 'sortDir must be asc or desc.'; return $res }
            $sortDir = $t
        }
        elseif ($k -eq 'filter') { $filter = $t }
        else { $node = $t }
    }
    if (-not $sortCol) { $sortDir = '' }
    $res.ok = $true
    $res.value = [ordered]@{ rows = $rows; sortCol = $sortCol; sortDir = $sortDir; filter = $filter; node = $node }
    return $res
}

function Read-UserSettingsFile {
    # doorkeeper-users.json: { "users": { "<aeos user, lowercase>": { settings } } }. A missing or broken file = no settings.
    $map = [ordered]@{}
    if ($script:UsersPath -and (Test-Path -LiteralPath $script:UsersPath)) {
        try {
            $o = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($script:UsersPath))
            if ($null -ne $o -and $null -ne $o.PSObject.Properties['users'] -and $null -ne $o.users) {
                foreach ($p in $o.users.PSObject.Properties) { $map[$p.Name] = $p.Value }
            }
        }
        catch { Write-DebugLog 'startup' ('User settings file not read: ' + $_.Exception.Message) 'WARN' }
    }
    $script:UserSettings = $map
}

function Save-UserSettingsFile {
    $text = ConvertTo-Json -InputObject ([ordered]@{ users = $script:UserSettings }) -Depth 5
    $dir = Split-Path -Parent $script:UsersPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $tmp = $script:UsersPath + '.tmp'
    [System.IO.File]::WriteAllText($tmp, $text, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $script:UsersPath) { [System.IO.File]::Replace($tmp, $script:UsersPath, [NullString]::Value) }
    else { [System.IO.File]::Move($tmp, $script:UsersPath) }
}

function Get-UserSettings {
    param([string]$User)
    $k = ([string]$User).Trim().ToLowerInvariant()
    if ($k -and $script:UserSettings -and $script:UserSettings.Contains($k)) { return $script:UserSettings[$k] }
    return $null
}

function Set-UserSettings {
    param([string]$User, $Value)
    $k = ([string]$User).Trim().ToLowerInvariant()
    if (-not $k) { throw (New-ApiException 401 'not_logged_in' 'Log in with the AEOS user first.') }
    if ($null -eq $script:UserSettings) { $script:UserSettings = [ordered]@{} }
    $script:UserSettings[$k] = $Value
    Save-UserSettingsFile
}

function Select-AuditRecords {
    # Filters for the Audit tab and its CSV export. User matches the AEOS or Windows user, Door matches id, name or alias
    # (all case-insensitive "contains"). Action: empty / all, opened (= unlock or access) or one action name.
    # From / To are UTC dates yyyy-MM-dd, both inclusive. A record that could not be read is never matched by a filter.
    param($Records, [string]$User = '', [string]$Door = '', [string]$Action = '', [string]$From = '', [string]$To = '')
    $out = @()
    $ci = [System.StringComparison]::OrdinalIgnoreCase
    foreach ($r in @($Records)) {
        if ($null -eq $r) { continue }
        $bad = [bool]$r.PSObject.Properties['parseError']
        if ($bad) { if (-not ($User -or $Door -or $Action -or $From -or $To)) { $out += $r }; continue }
        if ($User) {
            if (([string]$r.aeosUser).IndexOf($User, $ci) -lt 0 -and ([string]$r.windowsUser).IndexOf($User, $ci) -lt 0) { continue }
        }
        if ($Door) {
            if (([string]$r.doorId).IndexOf($Door, $ci) -lt 0 -and ([string]$r.doorName).IndexOf($Door, $ci) -lt 0 -and ([string]$r.doorAlias).IndexOf($Door, $ci) -lt 0) { continue }
        }
        if ($Action -and $Action -ne 'all') {
            $a = [string]$r.action
            if ($Action -eq 'opened') { if ($a -ne 'unlock' -and $a -ne 'access') { continue } }
            elseif (-not [string]::Equals($a, $Action, $ci)) { continue }
        }
        $day = ([string]$r.ts)
        if ($day.Length -ge 10) { $day = $day.Substring(0, 10) }
        if ($From -match '^\d{4}-\d\d-\d\d$' -and [string]::CompareOrdinal($day, $From) -lt 0) { continue }
        if ($To -match '^\d{4}-\d\d-\d\d$' -and [string]::CompareOrdinal($day, $To) -gt 0) { continue }
        $out += $r
    }
    return @($out)
}

function ConvertTo-AuditCsv {
    param($Records)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("time_utc,computer,client_ip,windows_user,aeos_user,action,door_id,door_name,door_alias,http_status,ok,fault,batch`r`n")
    foreach ($r in @($Records)) {
        if ($null -eq $r -or $r.PSObject.Properties['parseError']) { continue }
        $okText = 'false'
        if ($r.ok) { $okText = 'true' }
        $cells = @([string]$r.ts, [string]$r.computer, [string]$r.clientIp, [string]$r.windowsUser, [string]$r.aeosUser, [string]$r.action, [string]$r.doorId,
            [string]$r.doorName, [string]$r.doorAlias, [string]$r.httpStatus, $okText, [string]$r.fault, [string]$r.batch)
        [void]$sb.Append((($cells | ForEach-Object { ConvertTo-CsvCell $_ }) -join ',') + "`r`n")
    }
    return $sb.ToString()
}

function Update-StateCache {
    # Remembers the last state read of each door (memory now, doorkeeper-state-cache.json soon). A failed read ("?") is
    # not remembered. The cache only paints the page; it never enables an action.
    # Every write gets the next version number (the page asks for the entries newer than its last version). The cache and
    # the version counter are synchronized objects: the poller runspace writes to them too.
    # -ObservedAt = when the state was read (default now). An observation older than the cached one of that door is ignored, so
    # a slow poll round that ends after a door action cannot put the earlier state back.
    param($States, $ObservedAt = $null)
    if ($null -eq $script:StateCache) { $script:StateCache = [hashtable]::Synchronized(@{}) }
    if ($null -eq $script:StateMeta) { $script:StateMeta = [hashtable]::Synchronized(@{ Ver = 1; Dirty = $false }) }
    if ($null -eq $ObservedAt) { $ObservedAt = [DateTime]::UtcNow }
    $now = ([DateTime]$ObservedAt).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $ticks = ([DateTime]$ObservedAt).Ticks
    foreach ($s in @($States)) {
        if ($null -eq $s) { continue }
        $id = [string]$s.id
        $st = [string]$s.state
        if (-not $id -or -not $st -or $st -eq '?') { continue }
        $d = [string]$s.detail
        if ($d.Length -gt 200) { $d = $d.Substring(0, 200) }
        # version number and entry are stored under the same lock the since-answer is built under
        [System.Threading.Monitor]::Enter($script:StateCache.SyncRoot)
        try {
            $cur = $script:StateCache[$id]
            if ($null -ne $cur -and $cur.ContainsKey('t') -and [long]$cur.t -gt $ticks) { continue }
            $script:StateMeta.Ver = [int]$script:StateMeta.Ver + 1
            $ver = [int]$script:StateMeta.Ver
            $script:StateMeta.Dirty = $true
            $script:StateCache[$id] = @{ state = $st; detail = $d; at = $now; v = $ver; t = $ticks }
        }
        finally { [System.Threading.Monitor]::Exit($script:StateCache.SyncRoot) }
        $script:StateCacheDirty = $true
    }
}

function Get-LastKnownStates {
    # id -> @{ state; detail; at } for the listed doors that have a remembered state.
    param($Doors)
    $out = @{}
    if ($null -eq $script:StateCache) { return $out }
    foreach ($d in @($Doors)) {
        if ($null -eq $d) { continue }
        $id = [string]$d.id
        if ($id -and $script:StateCache.ContainsKey($id)) { $out[$id] = $script:StateCache[$id] }
    }
    return $out
}

function Save-StateCache {
    param([int]$MinAgeSec = 5)
    $metaDirty = ($null -ne $script:StateMeta -and $script:StateMeta.Dirty -eq $true)
    if ((-not $script:StateCacheDirty -and -not $metaDirty) -or -not $script:StateCachePath) { return }
    if ($null -ne $script:StateCacheSaved -and ([DateTime]::UtcNow - $script:StateCacheSaved).TotalSeconds -lt $MinAgeSec) { return }
    try {
        $snap = @{}
        [System.Threading.Monitor]::Enter($script:StateCache.SyncRoot)
        try { foreach ($k in @($script:StateCache.Keys)) { $e = $script:StateCache[$k]; $snap[$k] = @{ state = $e.state; detail = $e.detail; at = $e.at } } }
        finally { [System.Threading.Monitor]::Exit($script:StateCache.SyncRoot) }
        $text = ConvertTo-Json -InputObject @{ states = $snap } -Depth 5 -Compress
        $tmp = $script:StateCachePath + '.tmp'
        [System.IO.File]::WriteAllText($tmp, $text, (New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $script:StateCachePath) { [System.IO.File]::Replace($tmp, $script:StateCachePath, [NullString]::Value) }
        else { [System.IO.File]::Move($tmp, $script:StateCachePath) }
        $script:StateCacheDirty = $false
        if ($null -ne $script:StateMeta) { $script:StateMeta.Dirty = $false }
        $script:StateCacheSaved = [DateTime]::UtcNow
    }
    catch { Write-DebugLog 'state-cache' ('State cache not saved: ' + $_.Exception.Message) 'WARN' }
}

function Read-StateCacheFile {
    $script:StateCache = [hashtable]::Synchronized(@{})
    $script:StateMeta = [hashtable]::Synchronized(@{ Ver = 1; Dirty = $false })
    $script:StateCacheDirty = $false
    if ($script:StateCachePath -and (Test-Path -LiteralPath $script:StateCachePath)) {
        try {
            $o = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($script:StateCachePath))
            if ($null -ne $o -and $null -ne $o.PSObject.Properties['states'] -and $null -ne $o.states) {
                foreach ($p in $o.states.PSObject.Properties) {
                    $v = $p.Value
                    if ($null -ne $v -and [string]$v.state) { $script:StateCache[$p.Name] = @{ state = [string]$v.state; detail = [string]$v.detail; at = [string]$v.at; v = 1 } }
                }
            }
        }
        catch { Write-DebugLog 'startup' ('State cache file not read: ' + $_.Exception.Message) 'WARN' }
    }
}

# ============================================================================
# Hosting behind a reverse proxy (IIS): sessions, origin and forwarded-address checks, login rate limit, single instance,
# server account store (DPAPI), background jobs and the state poller (pure helpers first; unit tested)
# ============================================================================

function New-RandomHex {
    param([int]$Bytes = 32)
    $b = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-PublicOrigin {
    # scheme://host[:port] of -PublicUrl, lower case, default port dropped, no path. $null when it is not usable: only
    # https:// is accepted, plus http:// for localhost / 127.0.0.1 (tests and a first check on the server itself).
    param([string]$Url)
    if (-not $Url) { return $null }
    $u = $null
    if (-not [System.Uri]::TryCreate($Url.Trim(), [System.UriKind]::Absolute, [ref]$u)) { return $null }
    if ($u.Scheme -eq 'https') { return $u.GetLeftPart([System.UriPartial]::Authority) }
    if ($u.Scheme -eq 'http' -and ($u.Host -eq 'localhost' -or $u.Host -eq '127.0.0.1')) { return $u.GetLeftPart([System.UriPartial]::Authority) }
    return $null
}

function Test-OriginAllowed {
    # No Origin header = allowed (the page key still has to match); otherwise it must equal the allowed origin exactly.
    param([string]$Origin, [string]$Allowed)
    if (-not $Origin) { return $true }
    return ($Origin.TrimEnd('/') -ceq $Allowed.TrimEnd('/'))
}

function Test-CsrfToken {
    # Case-sensitive, constant-time compare of the page key (X-Console-Token) with the key of the session.
    param([string]$Expected, [string]$Supplied)
    if (-not $Expected -or $null -eq $Supplied -or $Expected.Length -ne $Supplied.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $Expected.Length; $i++) { $d = $d -bor ([int][char]$Expected[$i] -bxor [int][char]$Supplied[$i]) }
    return ($d -eq 0)
}

function Test-LocalProxyPeer {
    param([string]$RemoteAddr)
    return (@('127.0.0.1', '::1', '::ffff:127.0.0.1') -contains ([string]$RemoteAddr).Trim())
}

function Get-ForwardedClientIp {
    # The client address for the audit. Behind IIS EVERY request comes from 127.0.0.1, so "trust 127.0.0.1" alone would let a
    # browser forge the value. The sample web.config therefore has a URL Rewrite rule that OVERWRITES X-DK-Client-IP with
    # {REMOTE_ADDR} on every request; that single value is what is read here. Only with -BehindProxy and only on a request from
    # 127.0.0.1. Never X-Forwarded-For or any other client-sent header. An empty or invalid value (or a list) = the peer address.
    param([string]$RemoteAddr, [string]$ForwardedFor, [bool]$BehindProxy)
    if (-not $BehindProxy -or -not (Test-LocalProxyPeer -RemoteAddr $RemoteAddr)) { return [string]$RemoteAddr }
    $v = ([string]$ForwardedFor).Trim()
    if ($v -match '^(\d{1,3}(?:\.\d{1,3}){3}):\d+$') { $v = $Matches[1] }
    $ip = $null
    if ($v -and $v.IndexOf(',') -lt 0 -and [System.Net.IPAddress]::TryParse($v, [ref]$ip)) { return $ip.ToString() }
    return [string]$RemoteAddr
}
function Get-CookieValue {
    param([string]$Header, [string]$Name)
    foreach ($part in ([string]$Header -split ';')) {
        $kv = $part.Trim()
        $i = $kv.IndexOf('=')
        if ($i -gt 0 -and $kv.Substring(0, $i) -ceq $Name) { return $kv.Substring($i + 1) }
    }
    return ''
}

function New-SessionCookieHeader {
    # HttpOnly, SameSite=Strict, Path=/ ; Secure with -BehindProxy. -Clear ends the cookie in the browser.
    param([string]$Id, [bool]$Secure, [bool]$Clear = $false)
    if ($Clear) { $c = 'dk_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT' }
    else { $c = 'dk_session=' + $Id + '; Path=/; HttpOnly; SameSite=Strict' }
    if ($Secure) { $c += '; Secure' }
    return $c
}

function New-SessionRecord {
    # A session: random 32-byte id (the cookie), its own page key (X-Console-Token), the AEOS user and credential (memory
    # only), client address, Windows user (IIS), created and last-seen time.
    param($Cred, [string]$ClientIp = '', [string]$WindowsUser = '', $Now = $null)
    if ($null -eq $Now) { $Now = [DateTime]::UtcNow }
    return @{ Id = (New-RandomHex 32); Csrf = (New-RandomHex 32); User = [string]$Cred.UserName; Cred = $Cred; ClientIp = $ClientIp; WindowsUser = $WindowsUser; Created = $Now; LastSeen = $Now; DoorIds = @{} }
}

function Test-SessionExpired {
    # '' = still valid; 'idle' = no request for IdleMinutes; 'absolute' = older than AbsoluteHours (12 h).
    param($Session, $Now, [int]$IdleMinutes = 15, [int]$AbsoluteHours = 12)
    if (($Now - $Session.LastSeen).TotalMinutes -ge $IdleMinutes) { return 'idle' }
    if (($Now - $Session.Created).TotalHours -ge $AbsoluteHours) { return 'absolute' }
    return ''
}

function Get-IdleMinutes {
    $n = 15
    if ($null -ne $script:Config -and $null -ne $script:Config.PSObject.Properties['access'] -and $null -ne $script:Config.access) {
        [void][int]::TryParse([string]$script:Config.access.idleMinutes, [ref]$n)
    }
    if ($n -lt 1) { $n = 15 }
    return $n
}

function Find-Session {
    # Looks the cookie value up; an expired session is removed. Returns @{ Session; Expired } (Expired = idle | absolute).
    param([string]$Id, [switch]$NoTouch)
    $res = @{ Session = $null; Expired = '' }
    if ($null -eq $script:Sessions -or -not $Id -or $Id -notmatch '^[0-9a-f]{64}$') { return $res }
    if (-not $script:Sessions.ContainsKey($Id)) {
        # the sweeper may have removed an expired session already: it left a note with the reason
        if ($null -ne $script:ExpiredNotes -and $script:ExpiredNotes.ContainsKey($Id)) { $res.Expired = [string]$script:ExpiredNotes[$Id] }
        return $res
    }
    $s = $script:Sessions[$Id]
    $now = [DateTime]::UtcNow
    $why = Test-SessionExpired -Session $s -Now $now -IdleMinutes (Get-IdleMinutes)
    if ($why) { $script:Sessions.Remove($Id); $res.Expired = $why; return $res }
    if (-not $NoTouch) { $s.LastSeen = $now }
    $res.Session = $s
    return $res
}

function Remove-ExpiredSessions {
    if ($null -eq $script:Sessions) { return }
    $now = [DateTime]::UtcNow
    $idle = Get-IdleMinutes
    foreach ($k in @($script:Sessions.Keys)) {
        $why = Test-SessionExpired -Session $script:Sessions[$k] -Now $now -IdleMinutes $idle
        if ($why) {
            $script:Sessions.Remove($k)
            if ($null -eq $script:ExpiredNotes) { $script:ExpiredNotes = @{} }
            if ($script:ExpiredNotes.Count -gt 500) { $script:ExpiredNotes.Clear() }
            $script:ExpiredNotes[$k] = $why
        }
    }
}

# ---- login rate limit: 5 failures in 5 minutes block that user + client address pair for 5 minutes ----------------

function New-LoginAttemptEntry { return @{ Fails = (New-Object System.Collections.Generic.List[DateTime]); BlockedUntil = [DateTime]::MinValue } }

function Get-LoginBlockSeconds {
    param($Entry, $Now)
    if ($null -eq $Entry -or $Entry.BlockedUntil -le $Now) { return 0 }
    return [int][Math]::Ceiling(($Entry.BlockedUntil - $Now).TotalSeconds)
}

function Register-LoginFailure {
    # Records a failure; returns $true when this failure starts a block.
    param($Entry, $Now, [int]$Max = 5, [int]$WindowSec = 300, [int]$BlockSec = 300)
    $keep = New-Object System.Collections.Generic.List[DateTime]
    foreach ($t in $Entry.Fails) { if (($Now - $t).TotalSeconds -lt $WindowSec) { $keep.Add($t) } }
    $keep.Add($Now)
    $Entry.Fails = $keep
    if ($keep.Count -ge $Max) { $Entry.BlockedUntil = $Now.AddSeconds($BlockSec); $Entry.Fails = (New-Object System.Collections.Generic.List[DateTime]); return $true }
    return $false
}

function Get-LoginKey {
    param([string]$User, [string]$ClientIp)
    return (([string]$User).Trim().ToLowerInvariant() + '|' + [string]$ClientIp)
}

# ---- job bookkeeping (batch actions run as background jobs; the request loop only answers short requests) ---------

function New-JobRecord {
    # A synchronized hashtable: the worker runspace and the request thread both read and write it.
    param([string]$Id, [string]$User, [string]$Action, [int]$Total, $Now = $null)
    if ($null -eq $Now) { $Now = [DateTime]::UtcNow }
    return [hashtable]::Synchronized(@{
        Id = $Id; User = $User; Action = $Action; State = 'queued'; Phase = 'Queued'; Done = 0; Total = $Total
        StartedAt = $Now; FinishedAt = $null; Error = ''; ErrorCode = ''; ErrorStatus = 0; Result = $null; Cred = $null; Ps = $null; Rs = $null; Handle = $null
    })
}

function Test-JobActive {
    param($Job)
    return ($null -ne $Job -and (@('queued', 'running') -contains [string]$Job.State))
}

function Find-ActiveJobOfUser {
    # One job per operator at a time (user names compare without regard to letter case).
    param($Jobs, [string]$User)
    foreach ($j in @($Jobs.Values)) {
        if ((Test-JobActive -Job $j) -and [string]::Equals([string]$j.User, $User, [System.StringComparison]::OrdinalIgnoreCase)) { return $j }
    }
    return $null
}

function Get-JobPublic {
    # What the page may see of a job: no credential, no runspace objects.
    param($Job)
    $o = @{
        id = [string]$Job.Id; state = [string]$Job.State; phase = [string]$Job.Phase; action = [string]$Job.Action; user = [string]$Job.User
        done = [int]$Job.Done; total = [int]$Job.Total; startedAt = ([DateTime]$Job.StartedAt).ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($null -ne $Job.FinishedAt) { $o.finishedAt = ([DateTime]$Job.FinishedAt).ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Job.State -eq 'failed') { $o.error = @{ code = [string]$Job.ErrorCode; message = [string]$Job.Error } }
    if ($Job.State -eq 'done') { $o.result = $Job.Result }
    return $o
}

function Remove-OldJobs {
    # Finished jobs stay available for KeepMinutes; returns the number removed.
    param($Jobs, $Now, [int]$KeepMinutes = 60)
    $n = 0
    foreach ($k in @($Jobs.Keys)) {
        $j = $Jobs[$k]
        if ($null -ne $j.FinishedAt -and ($Now - [DateTime]$j.FinishedAt).TotalMinutes -ge $KeepMinutes) { $Jobs.Remove($k); $n++ }
    }
    return $n
}

# ---- single instance ---------------------------------------------------------------------------------------------

function Open-InstanceLock {
    # Takes an exclusive lock file; the returned stream must stay open for the life of the process. $null = another
    # instance holds it. -WaitSeconds covers an IIS recycle, where the new process starts before the old one is gone.
    param([string]$Path, [int]$WaitSeconds = 0)
    $end = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
    while ($true) {
        try {
            $dir = Split-Path -Parent $Path
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $b = (New-Object System.Text.UTF8Encoding($false)).GetBytes('pid ' + $PID + "`r`n")
            $fs.SetLength(0)
            $fs.Write($b, 0, $b.Length)
            $fs.Flush()
            return $fs
        }
        catch {
            if ([DateTime]::UtcNow -ge $end) { return $null }
            Start-Sleep -Milliseconds 250
        }
    }
}

# ---- server account (the AEOS user the console uses to read door states) ------------------------------------------

function Get-ServerAccountEntropy { return [System.Text.Encoding]::UTF8.GetBytes('DoorKeeper.ServerAccount.v1') }

function ConvertTo-ServerAccountBlob {
    # DPAPI, CurrentUser scope (the Windows account that runs DoorKeeper, the IIS app pool identity), fixed entropy.
    param($Cred, [byte[]]$Entropy = $null)
    if ($null -eq $Entropy) { $Entropy = Get-ServerAccountEntropy }
    Add-Type -AssemblyName System.Security
    $json = ConvertTo-Json -InputObject ([ordered]@{ user = [string]$Cred.UserName; password = [string]$Cred.GetNetworkCredential().Password }) -Compress
    $plain = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    try { return [System.Security.Cryptography.ProtectedData]::Protect($plain, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser) }
    finally { [Array]::Clear($plain, 0, $plain.Length) }
}

function ConvertFrom-ServerAccountBlob {
    # Never throws: @{ ok; cred; error }. A blob made by another Windows account (or with other entropy) does not decrypt.
    param([byte[]]$Blob, [byte[]]$Entropy = $null)
    $res = @{ ok = $false; cred = $null; error = '' }
    if ($null -eq $Entropy) { $Entropy = Get-ServerAccountEntropy }
    $plain = $null
    try {
        Add-Type -AssemblyName System.Security
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($Blob, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $o = ConvertFrom-Json -InputObject ((New-Object System.Text.UTF8Encoding($false)).GetString($plain))
        $u = [string]$o.user
        $pw = [string]$o.password
        if (-not $u -or -not $pw) { throw 'The stored account is incomplete.' }
        $ss = New-Object System.Security.SecureString
        foreach ($ch in $pw.ToCharArray()) { $ss.AppendChar($ch) }
        $ss.MakeReadOnly()
        $res.cred = New-Object System.Management.Automation.PSCredential($u, $ss)
        $res.ok = $true
    }
    catch { $res.error = 'The stored server account cannot be read (' + $_.Exception.GetType().Name + ').' }
    finally { if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) } }
    return $res
}

function Set-ServerAccountAcl {
    # Only the Windows account that runs DoorKeeper and the Administrators group; inheritance off. Returns '' or the reason.
    param([string]$Path)
    try {
        $sec = New-Object System.Security.AccessControl.FileSecurity
        $sec.SetAccessRuleProtection($true, $false)
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $adm = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        foreach ($sid in @($me, $adm)) {
            $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
        }
        (New-Object System.IO.FileInfo($Path)).SetAccessControl($sec)
        return ''
    }
    catch { return $_.Exception.Message }
}

function Save-ServerAccount {
    # Writes the DPAPI blob (ACL set before the file gets its final name) and a small meta file (who, when). The password
    # is in the blob only. Returns @{ aclError }.
    param($Cred, [string]$SetBy, [string]$BlobPath, [string]$MetaPath)
    $blob = ConvertTo-ServerAccountBlob -Cred $Cred
    $tmp = $BlobPath + '.tmp'
    [System.IO.File]::WriteAllBytes($tmp, $blob)
    $aclErr = Set-ServerAccountAcl -Path $tmp
    if (Test-Path -LiteralPath $BlobPath) { [System.IO.File]::Replace($tmp, $BlobPath, [NullString]::Value) }
    else { [System.IO.File]::Move($tmp, $BlobPath) }
    $meta = ConvertTo-Json -InputObject ([ordered]@{ setBy = $SetBy; setAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }) -Compress
    [System.IO.File]::WriteAllText($MetaPath, $meta, (New-Object System.Text.UTF8Encoding($false)))
    return @{ aclError = $aclErr }
}

function Read-ServerAccount {
    # @{ present; ok; cred; error; setBy; setAt }. present = the blob file exists; ok = it decrypted.
    param([string]$BlobPath, [string]$MetaPath)
    $res = @{ present = $false; ok = $false; cred = $null; error = ''; setBy = ''; setAt = '' }
    if (-not $BlobPath -or -not (Test-Path -LiteralPath $BlobPath)) { return $res }
    $res.present = $true
    if ($MetaPath -and (Test-Path -LiteralPath $MetaPath)) {
        try { $m = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($MetaPath)); $res.setBy = [string]$m.setBy; $res.setAt = [string]$m.setAt } catch { }
    }
    try { $blob = [System.IO.File]::ReadAllBytes($BlobPath) }
    catch { $res.error = 'The server account file cannot be read: ' + $_.Exception.Message; return $res }
    $d = ConvertFrom-ServerAccountBlob -Blob $blob
    $res.ok = $d.ok
    $res.cred = $d.cred
    $res.error = $d.error
    return $res
}

function Remove-ServerAccountFiles {
    param([string]$BlobPath, [string]$MetaPath)
    foreach ($p in @($BlobPath, $MetaPath)) { if ($p -and (Test-Path -LiteralPath $p)) { Remove-Item -LiteralPath $p -Force } }
}

function Get-ServerAccountStatus {
    # What an admin sees: never the user name's password, never the blob. state: none | running | login-failed |
    # starting | reenter (the stored account cannot be decrypted).
    $st = @{ set = $false; state = 'none'; setBy = ''; setAt = ''; lastLoginOkAt = ''; lastError = ''; message = 'No server account is set.' }
    $a = $script:ServerAccount
    if ($null -eq $a -or -not $a.present) { return $st }
    $st.set = $true
    $st.setBy = [string]$a.setBy
    $st.setAt = [string]$a.setAt
    if (-not $a.ok) {
        $st.state = 'reenter'
        $st.message = 'Server account must be entered again.'
        $st.lastError = [string]$a.error
        return $st
    }
    $p = $null
    if ($null -ne $script:Shared) { $p = $script:Shared.Poll }
    if ($null -eq $p -or -not $p.LastRoundAt) { $st.state = 'starting'; $st.message = 'The server account is set. The first read of the door states is starting.'; return $st }
    $st.lastLoginOkAt = [string]$p.LastLoginOkAt
    $st.lastError = [string]$p.Error
    if ($p.State -eq 'ok') { $st.state = 'running'; $st.message = 'The server account reads the door states.' }
    else { $st.state = 'login-failed'; $st.message = 'The last read of the door states failed.' }
    return $st
}

# ---- live states: the page asks for the changes since its last version --------------------------------------------

function Get-StateChanges {
    # id -> @{ state; detail; ageSec } for every cache entry newer than -Since (the version counter). The cache is
    # copied under its lock because the poller writes to it from another runspace.
    param([int]$Since, $Now = $null)
    if ($null -eq $Now) { $Now = [DateTime]::UtcNow }
    $out = @{}
    if ($null -eq $script:StateCache) { return $out }
    $lock = $script:StateCache.SyncRoot
    [System.Threading.Monitor]::Enter($lock)
    try {
        foreach ($k in @($script:StateCache.Keys)) {
            $e = $script:StateCache[$k]
            $v = 0
            if ($e.ContainsKey('v')) { $v = [int]$e.v }
            if ($v -le $Since) { continue }
            $age = 999999
            $at = [DateTime]::MinValue
            if ([DateTime]::TryParse([string]$e.at, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at)) {
                $age = [int][Math]::Max(0, ($Now - $at).TotalSeconds)
            }
            $out[$k] = @{ state = [string]$e.state; detail = [string]$e.detail; ageSec = $age }
        }
    }
    finally { [System.Threading.Monitor]::Exit($lock) }
    return $out
}

# ---- the server's own door list: the routes take door ids and use name / extra from here, never from the client ----

function Set-ServerDoors {
    # Merges doors read by a listDoors call (by id) into the shared list. A new table is built and swapped in.
    param($Doors)
    if ($null -eq $script:Shared) { return }
    [System.Threading.Monitor]::Enter($script:Shared)
    try {
        $m = @{}
        $cur = $script:Shared.DoorMap
        if ($null -ne $cur) { foreach ($k in $cur.Keys) { $m[$k] = $cur[$k] } }
        foreach ($d in @($Doors)) {
            if ($null -eq $d -or -not [string]$d.id) { continue }
            $m[[string]$d.id] = [pscustomobject]@{ id = [string]$d.id; name = [string]$d.name; extra = $d.extra }
        }
        $script:Shared.DoorMap = $m
    }
    finally { [System.Threading.Monitor]::Exit($script:Shared) }
}

function Resolve-ServerDoors {
    # Door ids (or door objects: only the id is used) -> the server's own door objects. An unknown id is a 400 unknown_door.
    # -Allowed (the door ids this session listed itself) limits it further; $null = no limit (no session).
    param($Requested, $Map, $Allowed = $null)
    $out = @()
    foreach ($r in @($Requested)) {
        if ($null -eq $r) { continue }
        $id = ''
        if ($r -is [string]) { $id = $r } elseif ($null -ne $r.PSObject.Properties['id']) { $id = [string]$r.id }
        if (-not $id -or $null -eq $Map -or -not $Map.ContainsKey($id) -or ($null -ne $Allowed -and -not $Allowed.ContainsKey($id))) {
            throw (New-ApiException 400 'unknown_door' ('The door "' + $id + '" is not in the door list of the server. Load doors again. Nothing was sent.'))
        }
        $out += $Map[$id]
    }
    return @($out)
}

function Get-StateAnswer {
    # The version and the changes since -Since from ONE locked read (a writer cannot slip between them), limited to the door
    # ids -Allowed (the doors this session listed itself); no list = nothing.
    param([int]$Since, $Allowed)
    $lock = $null
    if ($null -ne $script:StateCache) { $lock = $script:StateCache.SyncRoot }
    if ($null -eq $lock) { return @{ ver = (Get-StateVersion); states = @{} } }
    [System.Threading.Monitor]::Enter($lock)
    try {
        $ver = Get-StateVersion
        $all = Get-StateChanges -Since $Since
    }
    finally { [System.Threading.Monitor]::Exit($lock) }
    return @{ ver = $ver; states = (Select-StatesForIds -States $all -Ids $Allowed) }
}

function Select-StatesForIds {
    param($States, $Ids)
    $out = @{}
    if ($null -eq $Ids) { return $out }
    foreach ($k in @($States.Keys)) { if ($Ids.ContainsKey([string]$k)) { $out[$k] = $States[$k] } }
    return $out
}

function Get-CachedStates {
    # id -> @{ id; state; detail; ageSec } straight from the cache (live mode answers a state request from here).
    param($Ids)
    $now = [DateTime]::UtcNow
    $out = @()
    foreach ($id in @($Ids)) {
        $e = $null
        if ($null -ne $script:StateCache -and $script:StateCache.ContainsKey([string]$id)) { $e = $script:StateCache[[string]$id] }
        if ($null -eq $e) { $out += @{ id = [string]$id; state = '?'; detail = 'Not read yet: the server is reading it.'; ageSec = 999999 }; continue }
        $age = 999999
        $at = [DateTime]::MinValue
        if ([DateTime]::TryParse([string]$e.at, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at)) { $age = [int][Math]::Max(0, ($now - $at).TotalSeconds) }
        $out += @{ id = [string]$id; state = [string]$e.state; detail = [string]$e.detail; ageSec = $age }
    }
    return @($out)
}

function Get-StateVersion {
    if ($null -eq $script:StateMeta) { return 1 }
    return [int]$script:StateMeta.Ver
}

function Get-PollSettings {
    $r = @{ pollSeconds = 30; freshSeconds = 120 }
    if ($null -ne $script:Config -and $null -ne $script:Config.PSObject.Properties['doorState'] -and $null -ne $script:Config.doorState) {
        $n = 0
        if ([int]::TryParse([string]$script:Config.doorState.pollSeconds, [ref]$n) -and $n -ge 1) { $r.pollSeconds = $n }
        if ([int]::TryParse([string]$script:Config.doorState.freshSeconds, [ref]$n) -and $n -ge 5) { $r.freshSeconds = $n }
    }
    return $r
}

function Test-ServerAccountSet {
    return ($null -ne $script:Shared -and $null -ne $script:Shared.Account)
}

function Test-LiveStates {
    # The page may rely on the server's live states: the server account reads them and its last round was recent.
    if ($null -eq $script:Shared -or $null -eq $script:Shared.Account) { return $false }
    $p = $script:Shared.Poll
    if ($p.State -ne 'ok' -or -not $p.LastOkUtc) { return $false }
    $ps = Get-PollSettings
    $limit = [Math]::Max(30, 4 * $ps.pollSeconds)
    return (([DateTime]::UtcNow - [DateTime]$p.LastOkUtc).TotalSeconds -le $limit)
}

# ---- worker runspaces (batch jobs and the state poller). The functions of this file are copied into each runspace. --

function Get-ScriptFunctionDefs {
    # name -> function body text of every top-level function of this script file (the same trick as tests\Test-Unit.ps1).
    param([string]$Path)
    $tokens = $null
    $perrs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$perrs)
    $defs = [ordered]@{}
    foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        $t = $f.Body.Extent.Text
        $defs[$f.Name] = $t.Substring(1, $t.Length - 2)
    }
    return $defs
}

function New-WorkerRunspace {
    # A runspace with every function of this script and the given global variables (the functions read them as $script:X).
    param([hashtable]$Variables)
    if ($null -eq $script:FunctionDefs) { $script:FunctionDefs = Get-ScriptFunctionDefs -Path $script:SelfPath }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($n in $script:FunctionDefs.Keys) {
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($n, [string]$script:FunctionDefs[$n])))
    }
    foreach ($k in $Variables.Keys) {
        $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($k, $Variables[$k], '')))
    }
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
    $rs.ApartmentState = [System.Threading.ApartmentState]::MTA
    $rs.Open()
    return $rs
}

function Get-WorkerVariables {
    # The script state every worker needs. Config is the object at the moment of the call.
    $v = @{
        Config = $script:Config; StateCache = $script:StateCache; StateMeta = $script:StateMeta; AuditShared = $script:AuditShared
        AuditPath = $script:AuditPath; LastAuditHash = $script:LastAuditHash; DebugLogPath = $script:DebugLogPath; DataDir = $script:DataDir
        ScriptDir = $script:ScriptDir; Version = $script:Version; ZeroHash = $script:ZeroHash; ActionNames = $script:ActionNames
        LogLock = $script:LogLock; Shared = $script:Shared; BehindProxy = $script:BehindProxy; LastDoorCount = 0
    }
    return $v
}

$script:BatchWorkerText = @'
$ErrorActionPreference = 'Stop'
$j = $script:Job
try {
    $script:Cred = $j.Cred
    $script:RequestClient = $j.Client
    $j.State = 'running'
    $j.Phase = 'Sending'
    $cb = { param($done, $total, $phase) $script:Job.Done = [int]$done; $script:Job.Total = [int]$total; $script:Job.Phase = [string]$phase }
    $r = Invoke-DoorBatch -Rid $j.Id -Action $j.Action -Doors @($j.Doors) -Report $j.Report -OnProgress $cb
    $j.Result = $r
    $j.Done = [int]$j.Total
    $j.Phase = 'Done'
    $j.FinishedAt = [DateTime]::UtcNow
    $j.State = 'done'
}
catch {
    $e = $_.Exception
    $j.ErrorCode = 'internal'
    $j.ErrorStatus = 500
    if ($e.Data -and $e.Data.Contains('code')) { $j.ErrorCode = [string]$e.Data['code']; $j.ErrorStatus = [int]$e.Data['status'] }
    $j.Error = [string]$e.Message
    Write-DebugLog $j.Id ('Batch job failed: ' + $e.Message + "`r`n" + (Format-ExceptionDetail $e)) 'ERROR'
    $j.Phase = 'Failed'
    $j.FinishedAt = [DateTime]::UtcNow
    $j.State = 'failed'
}
finally { $script:Cred = $null }
'@

function Start-BatchJob {
    # Starts the batch in its own runspace and returns at once. The job carries the operator's own credential.
    param($Job, $Doors, $Report, $Cred, $Client)
    $Job.Cred = $Cred
    $Job.Doors = $Doors
    $Job.Report = $Report
    $Job.Client = $Client
    $vars = Get-WorkerVariables
    $vars.Job = $Job
    $rs = New-WorkerRunspace -Variables $vars
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($script:BatchWorkerText)
    $Job.Rs = $rs
    $Job.Ps = $ps
    $Job.Handle = $ps.BeginInvoke()
}

function Complete-FinishedJobs {
    # Called from the request loop: frees the runspace of a job that has ended and drops old finished jobs.
    if ($null -eq $script:Jobs) { return }
    foreach ($j in @($script:Jobs.Values)) {
        if ($null -ne $j.Ps -and -not (Test-JobActive -Job $j) -and $j.Handle.IsCompleted) {
            try { [void]$j.Ps.EndInvoke($j.Handle) } catch { }
            try { $j.Ps.Dispose() } catch { }
            try { $j.Rs.Close(); $j.Rs.Dispose() } catch { }
            $j.Ps = $null
            $j.Rs = $null
            $j.Cred = $null
        }
    }
    [void](Remove-OldJobs -Jobs $script:Jobs -Now ([DateTime]::UtcNow))
}

$script:PollerWorkerText = @'
$ErrorActionPreference = 'Continue'
$sh = $script:Shared
$script:DebugQuiet = $true
$lastErr = ''
$doors = $null
$doorsAt = [DateTime]::MinValue
while (-not $sh.Stop) {
    $gen = $sh.AccountGen
    $cred = $sh.Account
    if ($null -eq $cred) { $script:Cred = $null; $script:RoundGen = $null; $sh.Poll.State = 'idle'; Start-Sleep -Milliseconds 500; continue }
    $script:Cred = $cred
    $script:RoundGen = $gen
    $script:Config = $sh.Config
    $ps = Get-PollSettings
    $t0 = [DateTime]::UtcNow
    try {
        if (@(Get-DoorStateChecks).Count -eq 0) { throw 'No door state checks are set (Setup, Door state).' }
        if ($null -eq $doors -or ($t0 - $doorsAt).TotalSeconds -ge 600 -or $sh.RelistDoors) {
            $sh.RelistDoors = $false
            $dl = Get-DoorsFromServer -Rid 'poll'
            if (-not $dl.ok) { throw ('The door list was refused: ' + $(if ($dl.fault) { $dl.fault } else { 'HTTP ' + $dl.httpStatus })) }
            $doors = @($dl.doors | ForEach-Object { [pscustomobject]@{ id = [string]$_.id; name = [string]$_.name; extra = $_.extra } })
            $doorsAt = $t0
        }
        $res = Get-DoorStates -Rid 'poll' -Doors $doors
        $good = @($res.states | Where-Object { $_.state -ne '?' }).Count
        $bad = @($res.states | Where-Object { $_.state -eq '?' })
        $sh.Poll.LastRoundAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $sh.Poll.LastRoundMs = [int]([DateTime]::UtcNow - $t0).TotalMilliseconds
        $sh.Poll.Doors = $doors.Count
        if ($good -gt 0) {
            $sh.Poll.State = 'ok'; $sh.Poll.Error = ''
            $sh.Poll.LastLoginOkAt = $sh.Poll.LastRoundAt
            $sh.Poll.LastOkUtc = [DateTime]::UtcNow
            if ($bad.Count -gt 0) { $sh.Poll.Error = ($bad.Count.ToString() + ' door(s) not read: ' + [string]$bad[0].detail) }
        }
        elseif ($bad.Count -gt 0) { throw ([string]$bad[0].detail) }
    }
    catch {
        $m = Protect-Text -Text ([string]$_.Exception.Message)
        $sh.Poll.State = 'error'
        $sh.Poll.Error = $m
        $sh.Poll.LastRoundAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        if ($m -ne $lastErr) { Write-DebugLog 'poll' ('Live state read failed: ' + $m) 'NOTE' }
    }
    if ($sh.Poll.State -eq 'ok' -and $lastErr) { Write-DebugLog 'poll' 'Live state read works again.' 'NOTE' }
    $script:Cred = $null
    $script:RoundGen = $null
    $lastErr = $(if ($sh.Poll.State -eq 'ok') { '' } else { [string]$sh.Poll.Error })
    # wait the poll pause; a door that was just acted on (SOAP) is re-read at once
    $until = [DateTime]::UtcNow.AddSeconds($ps.pollSeconds)
    while (-not $sh.Stop -and [DateTime]::UtcNow -lt $until) {
        $item = $null
        $got = @()
        $map = $sh.DoorMap
        # the queue holds door ids only; name and extra come from the server's own door list, unknown ids are skipped
        while ($sh.Priority.TryDequeue([ref]$item)) { if ($null -ne $map -and $map.ContainsKey([string]$item)) { $got += $map[[string]$item] } }
        if ($got.Count -gt 0 -and $null -ne $sh.Account) {
            $script:Cred = $sh.Account
            $script:RoundGen = $sh.AccountGen
            try { [void](Get-DoorStates -Rid 'poll' -Doors $got) } catch { }
            finally { $script:Cred = $null; $script:RoundGen = $null }
        }
        if ($sh.Wake) { $sh.Wake = $false; break }
        Start-Sleep -Milliseconds 300
    }
}
'@

function New-SharedState {
    # The object the request thread and the poller runspace share.
    $sh = [hashtable]::Synchronized(@{
        Stop = $false; Account = $null; AccountGen = 0; Config = $script:Config; RelistDoors = $false; Wake = $false
        Priority = (New-Object System.Collections.Concurrent.ConcurrentQueue[object]); ReportOwners = [hashtable]::Synchronized(@{}); DoorMap = $null
        Poll = [hashtable]::Synchronized(@{ State = 'idle'; Error = ''; LastRoundAt = ''; LastRoundMs = 0; Doors = 0; LastLoginOkAt = ''; LastOkUtc = $null })
    })
    return $sh
}

function Start-StatePoller {
    if ($null -ne $script:PollerPs) { return }
    $rs = New-WorkerRunspace -Variables (Get-WorkerVariables)
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($script:PollerWorkerText)
    $script:PollerRs = $rs
    $script:PollerPs = $ps
    $script:PollerHandle = $ps.BeginInvoke()
}

function Stop-StatePoller {
    if ($null -ne $script:Shared) { $script:Shared.Stop = $true }
    if ($null -ne $script:PollerPs) {
        try { [void]$script:PollerHandle.AsyncWaitHandle.WaitOne(3000) } catch { }
        try { $script:PollerPs.Stop() } catch { }
        try { $script:PollerPs.Dispose() } catch { }
        try { $script:PollerRs.Close(); $script:PollerRs.Dispose() } catch { }
    }
    $script:PollerPs = $null
}

function Set-PollerAccount {
    # $null removes the account (the poller idles); a credential (re)starts it.
    param($Cred)
    $script:Shared.Account = $Cred
    $script:Shared.AccountGen = [int]$script:Shared.AccountGen + 1
    $script:Shared.Config = $script:Config
    $script:Shared.RelistDoors = $true
    $script:Shared.Wake = $true
    $script:Shared.Poll.State = 'idle'
    $script:Shared.Poll.Error = ''
    $script:Shared.Poll.LastRoundAt = ''
    $script:Shared.Poll.LastOkUtc = $null
    $script:Shared.Poll.LastLoginOkAt = ''
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
    # -JobId (the batch job, 8 hex characters) is part of the file name; the file is created with CreateNew so two reports can
    # never overwrite each other. -Owner (the operator) is remembered for the download check.
    param([string]$Label, [string]$Action, $Rows, [string]$JobId = '', [string]$Owner = '')
    $dir = Split-Path -Parent $script:AuditPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $now = [DateTime]::UtcNow
    $base = 'doorkeeper-arming-' + $now.ToString('yyyyMMdd-HHmmss')
    if ($JobId -match '^[0-9a-f]{8}$') { $base += '-' + $JobId }
    $ts = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("time,action,group_or_selection,door_id,door_name,door_alias,location,ok,reply_or_fault,state_after`r`n")
    foreach ($row in @($Rows)) {
        $loc = Get-DoorLocation -Door $row.Door -Locations $script:Config.locations
        $why = [string]$row.Reply
        if (-not $row.Ok) { $why = [string]$row.Fault }
        $okText = 'false'
        if ($row.Ok) { $okText = 'true' }
        $cells = @($ts, $Action, $Label, $row.Id, $row.Name, (Get-DoorAlias -Id ([string]$row.Id)), $loc.Text, $okText, $why, [string]$row.State)
        [void]$sb.Append((($cells | ForEach-Object { ConvertTo-CsvCell $_ }) -join ',') + "`r`n")
    }
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($sb.ToString())
    $name = $base + '.csv'
    $n = 1
    while ($true) {
        try {
            $fs = [System.IO.File]::Open((Join-Path $dir $name), [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Close() }
            break
        }
        catch [System.IO.IOException] {
            if (-not (Test-Path -LiteralPath (Join-Path $dir $name))) { throw }
            $n++
            $name = $base + '-' + $n + '.csv'
        }
    }
    if ($Owner -and $null -ne $script:Shared -and $null -ne $script:Shared.ReportOwners) { $script:Shared.ReportOwners[$name] = $Owner }
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
    $sa = $null
    if ($null -ne $script:Shared) { $sa = $script:Shared.Account }
    if ($null -ne $sa) {
        try {
            $nc2 = $sa.GetNetworkCredential()
            if ($nc2.Password) {
                $list.Add($nc2.Password)
                $list.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($nc2.UserName + ':' + $nc2.Password)))
            }
        }
        catch { }
    }
    return $list.ToArray()
}

function Protect-Text {
    # ONLY for text that comes from AEOS or the network, applied where it is captured (SOAP response / fault, socket replies and
    # transcripts, exception messages of the connection, TLS and parsing, poller errors) - never for text that holds request input:
    # a blanket pass over answers would show an operator whether a guess equals the server account password.
    # Replaces the password of the credential of this request / job and of the server account (and its Basic-auth form) with
    # ****, so no AEOS error text that echoes a credential is logged, audited, returned or stored.
    param([string]$Text)
    if (-not $Text) { return '' }
    return (Hide-Secrets -Text $Text -Secrets @(Get-RedactionSecrets))
}

function Protect-Transcript {
    # Socket transcript: RECV lines come from AEOS and are masked; SEND lines are what we sent (an admin's own typed command) and
    # stay as sent - a blanket pass would show a typed guess of the server password as "****". The login SEND line is already
    # masked at its source (LoginShown).
    param([string[]]$Lines)
    $out = @()
    foreach ($l in @($Lines)) {
        if ([string]$l -like 'RECV *') { $out += (Protect-Text -Text ([string]$l)) } else { $out += [string]$l }
    }
    return @($out)
}

function Write-DebugLog {
    param([string]$Rid, [string]$Message, [string]$Level = 'INFO')
    if (-not $script:DebugLogPath) { return }
    # The poller runspace logs only warnings, errors and NOTE lines (a state round would write thousands of lines).
    if ($script:DebugQuiet -and $Level -eq 'INFO') { return }
    $lockObj = $script:LogLock
    $locked = $false
    try {
        if ($null -ne $lockObj) { $locked = [System.Threading.Monitor]::TryEnter($lockObj, 2000) }
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
    finally { if ($locked) { [System.Threading.Monitor]::Exit($lockObj) } }
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
    # Paths of the audit and debug files. The head of the audit chain is read only for a path that has not been read yet (the
    # first start, or a real change of auditFile): a config save with the same path keeps the head in memory, because a job may be
    # appending at that moment. Head read and appends use the same lock.
    $newAudit = Resolve-DataPath -Value ([string]$script:Config.auditFile) -BaseDir $script:ScriptDir -DefaultName 'doorkeeper-audit.jsonl'
    $script:DebugLogPath = Resolve-DataPath -Value ([string]$script:Config.debugLogFile) -BaseDir $script:ScriptDir -DefaultName 'doorkeeper-debug.log'
    if ($null -eq $script:AuditShared) { $script:AuditShared = [hashtable]::Synchronized(@{ Hash = $script:ZeroHash; Path = '' }) }
    [System.Threading.Monitor]::Enter($script:AuditShared)
    try {
        if ([string]$script:AuditShared.Path -ne $newAudit) {
            $script:AuditPath = $newAudit
            $script:LastAuditHash = $script:ZeroHash
            $recs = @(Read-AuditRecords)
            if ($recs.Count -gt 0) {
                $last = $recs[$recs.Count - 1]
                if (-not $last.PSObject.Properties['parseError'] -and $last.hash) { $script:LastAuditHash = [string]$last.hash }
            }
            $script:AuditShared.Hash = $script:LastAuditHash
            $script:AuditShared.Path = $newAudit
        }
    }
    finally { [System.Threading.Monitor]::Exit($script:AuditShared) }
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
    # Every new record is v4 (the hash covers every field, fault included): it also holds the computer name (where the console runs, so "from where"), the door alias and
    # the client address (clientIp) of the request. windowsUser is the Windows user IIS passed for the request when the
    # console runs behind IIS, else the account that runs the console. The writes of the request thread and of the batch
    # job runspaces are serialized by one lock, and the hash chain continues from the shared last hash.
    # -AeosUser is for a login that was refused (no credential is kept then).
    param([string]$Action, [string]$DoorId, [string]$DoorName, [int]$HttpStatus, [bool]$Ok, [string]$Fault, [string]$Batch = '',
        [string]$AeosUser = '', [string]$DoorAlias = '')
    $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $win = [Environment]::UserDomainName + '\' + [Environment]::UserName
    $clientIp = ''
    if ($null -ne $script:RequestClient) {
        $clientIp = [string]$script:RequestClient.Ip
        if ($null -ne $script:RequestClient.WindowsUser) { $win = [string]$script:RequestClient.WindowsUser }
    }
    $aeos = $AeosUser
    if (-not $aeos -and $null -ne $script:Cred) { $aeos = $script:Cred.UserName }
    if (-not $DoorAlias -and $DoorId) { $DoorAlias = Get-DoorAlias -Id $DoorId }
    $computer = [string]$env:COMPUTERNAME
    $shared = $script:AuditShared
    $lockObj = $shared
    if ($null -eq $lockObj) { $lockObj = $script:AuditPath }
    [System.Threading.Monitor]::Enter($lockObj)
    try {
        $prev = $script:LastAuditHash
        if ($null -ne $shared -and $shared.Hash) { $prev = [string]$shared.Hash }
        $hash = Get-AuditHash -PrevHash $prev -Ts $ts -WindowsUser $win -AeosUser $aeos -Action $Action -DoorId $DoorId -DoorName $DoorName -HttpStatus $HttpStatus -Ok $Ok -Batch $Batch `
            -Version 4 -Computer $computer -DoorAlias $DoorAlias -ClientIp $clientIp -Fault $Fault
        $rec = [ordered]@{
            v = 4; ts = $ts; windowsUser = $win; computer = $computer; clientIp = $clientIp; aeosUser = $aeos; action = $Action; doorId = $DoorId; doorName = $DoorName; doorAlias = $DoorAlias
            httpStatus = $HttpStatus; ok = $Ok; fault = $Fault; prevHash = $prev; hash = $hash
        }
        if ($Batch) { $rec['batch'] = $Batch }
        $line = ConvertTo-Json -InputObject $rec -Compress
        $dir = Split-Path -Parent $script:AuditPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        [System.IO.File]::AppendAllText($script:AuditPath, $line + "`n", (New-Object System.Text.UTF8Encoding($false)))
        $script:LastAuditHash = $hash
        if ($null -ne $shared) { $shared.Hash = $hash }
    }
    finally { [System.Threading.Monitor]::Exit($lockObj) }
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
        throw (New-ApiException 502 'aeos_unreachable' ('Cannot send the request to AEOS: ' + (Protect-Text -Text $_.Exception.Message)))
    }
    $sw.Stop()
    foreach ($l in $cb.Lines) { Write-DebugLog $Rid $l }
    if ($null -eq $resp) {
        $msgs = New-Object System.Collections.Generic.List[string]
        $e = $webEx
        while ($null -ne $e) { $msgs.Add($e.Message); $e = $e.InnerException }
        Write-DebugLog $Rid ('!!! NO RESPONSE [' + $What + '] after ' + $sw.ElapsedMilliseconds + ' ms' + "`r`n" + (Format-ExceptionDetail $webEx)) 'ERROR'
        throw (New-ApiException 502 'aeos_unreachable' ('Cannot reach AEOS (' + $webEx.Status + '): ' + (Protect-Text -Text ($msgs -join ' -> '))))
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
    if ($fault) { $fault = Protect-Text -Text $fault }
    Write-DebugLog $Rid ('Call result [' + $What + ']: httpStatus=' + $r.Status + ' ok=' + $ok + $(if ($fault) { ' fault="' + $fault + '"' } else { '' }))
    return @{ httpStatus = $r.Status; ok = $ok; fault = $fault; response = (Protect-Text -Text (Format-XmlPretty $r.Body)); rawText = (Protect-Text -Text $r.Body) }
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
    $matched = @{}
    foreach ($c in @($Commands)) {
        $i++
        $r = [pscustomobject]@{ Key = $c.Key; Sent = $false; Ok = $false; Reply = ''; Fault = $null }
        $grp = ''
        if ($c -is [System.Collections.IDictionary] -and $c.Contains('StopGroup')) { $grp = [string]$c['StopGroup'] }
        # A command with a StopGroup is skipped (Ok, not sent) once an earlier command of that group had a reply that
        # matched its StopPattern: Resolve-DoorState stops at the first matching check, so the skipped ones are never read.
        if ($grp -and $matched.ContainsKey($grp)) { $r.Ok = $true; $results.Add($r); continue }
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
            if ($grp -and $c['StopPattern'] -and [regex]::IsMatch($reply, [string]$c['StopPattern'])) { $matched[$grp] = $true }
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
            throw (New-ApiException 502 'socket_unreachable' ('Cannot connect to the AEOS socket ' + $hostName + ':' + $port + ': ' + (Protect-Text -Text $_.Exception.Message)))
        }
        Write-DebugLog $Rid ('SOCKET connected to ' + $tcp.Client.RemoteEndPoint)
        if ($useTls) {
            Initialize-TlsCallbackType
            $cb = New-Object AeosTlsCallback
            $cb.Skip = ($sk.tlsSkipValidation -eq $true)
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb.Callback)
            try {
                # bounded by the connect timeout: a server that accepts the connection and then says nothing must not hold the request
                $hs = $ssl.BeginAuthenticateAsClient($hostName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false, $null, $null)
                if (-not $hs.AsyncWaitHandle.WaitOne($tmo)) {
                    try { $tcp.Close() } catch { }
                    throw ('no TLS handshake within ' + $cfg.timeoutSec + ' s')
                }
                $ssl.EndAuthenticateAsClient($hs)
            }
            catch {
                foreach ($l in $cb.Lines) { Write-DebugLog $Rid $l }
                Write-DebugLog $Rid ('!!! SOCKET TLS handshake failed' + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
                $m = $_.Exception.Message
                $ie = $_.Exception.InnerException
                while ($null -ne $ie) { $m = $m + ' -> ' + $ie.Message; $ie = $ie.InnerException }
                $hint = ''
                if (-not $cb.Skip) { $hint = ' (self-signed AEOS certificate? tick "Skip TLS certificate validation" in the Socket interface settings)' }
                throw (New-ApiException 502 'socket_tls' ('TLS handshake with the AEOS socket failed: ' + (Protect-Text -Text $m) + $hint))
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
    # replies, faults and the transcript come from AEOS: masked here, before anything combines or stores them
    foreach ($rr in @($results)) {
        if ($null -ne $rr.Reply) { $rr.Reply = Protect-Text -Text ([string]$rr.Reply) }
        if ($rr.Fault) { $rr.Fault = Protect-Text -Text ([string]$rr.Fault) }
    }
    if ($session.Fault) { $session.Fault = Protect-Text -Text ([string]$session.Fault) }
    $session.Transcript = @(Protect-Transcript -Lines @($session.Transcript.ToArray()))
    $out.results = @($results)
    $bad = @($results | Where-Object { -not $_.Ok })
    $out.ok = ($results.Count -gt 0 -and $bad.Count -eq 0)
    if ($results.Count -gt 0) { $out.reply = [string]$results[0].Reply }
    $out.fault = $session.Fault
    if (-not $out.fault -and $bad.Count -gt 0) { $out.fault = [string]$bad[0].Fault }
    $out.transcript = @($session.Transcript)
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
    # With -Checks each command also carries StopGroup (the door) and StopPattern (the check's match pattern): the session
    # sends the checks of a door one by one and skips the rest of that door once a reply matches (a Locked door needs one command).
    param($Plan, $Checks = $null)
    $cmds = @()
    $chk = @($Checks)
    $di = 0
    foreach ($p in @($Plan)) {
        $ci = 0
        foreach ($t in @($p.Commands)) {
            $c = @{ Text = [string]$t; Shown = [string]$t; Pattern = ''; Key = ('state:' + $di + ':' + $ci) }
            if ($null -ne $Checks -and $ci -lt $chk.Count) { $c.StopGroup = ('state:' + $di); $c.StopPattern = [string]$chk[$ci].matchPattern }
            $cmds += $c
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

function Assert-RoundCurrent {
    # A poller round belongs to one server account: when the account is replaced or removed the round stops and stores nothing.
    if ($null -ne $script:RoundGen -and $null -ne $script:Shared -and [int]$script:Shared.AccountGen -ne [int]$script:RoundGen) {
        throw (New-ApiException 409 'account_changed' 'The server account changed during the read.')
    }
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
    $obs0 = [DateTime]::UtcNow
    for ($off = 0; $off -lt $list.Count; $off += $max) {
        Assert-RoundCurrent
        $part = @($list[$off..([Math]::Min($off + $max, $list.Count) - 1)])
        $plan = @(Get-DoorStatePlan -Doors $part -Checks $checks)
        $cmds = @(Get-DoorStateCommands -Plan $plan -Checks $checks)
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
    Assert-RoundCurrent
    Update-StateCache -States $states -ObservedAt $obs0
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
        $commands += @(Get-DoorStateCommands -Plan $plan -Checks $checks)
    }
    $sess = Invoke-SocketSession -Rid $Rid -What $Action -LoginText $login.Text -LoginShown $login.Shown -Commands $commands
    $r0 = $sess.results[0]
    $res = @{ ok = [bool]$r0.Ok; reply = [string]$r0.Reply; fault = $null; transcript = $sess.transcript; state = $null; stateDetail = '' }
    if (-not $r0.Ok) { $res.fault = $sess.fault; if (-not $res.fault) { $res.fault = [string]$r0.Fault } }
    if ($checks.Count -gt 0) {
        $st = @(Get-DoorStatesFromResults -Plan $plan -Checks $checks -Results @($sess.results | Select-Object -Skip 1) -OtherwiseLabel ([string]$script:Config.doorState.otherwiseLabel))
        $res.state = [string]$st[0].state
        $res.stateDetail = [string]$st[0].detail
        Update-StateCache -States $st
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

function Test-AeosLogin {
    # Checks the typed credential (already in $script:Cred) against AEOS before it is kept. Socket interface set up with a
    # login command that holds {{password}}: one session with only the login; its reply must match the login success pattern.
    # Otherwise, when the list doors action is mapped: one list doors call, which must not answer 401 or 403.
    # With neither there is nothing to check against yet (first setup): the login is accepted, as before.
    # Returns @{ ok; checked; refused; reason }. A connection failure throws the API exception.
    param([string]$Rid)
    $cfg = $script:Config
    $sk = $cfg.socket
    $port = 0
    [void][int]::TryParse([string]$sk.port, [ref]$port)
    $tpl = [string]$sk.loginTemplate
    # An EMPTY login success pattern is not a check (any reply would pass): the socket is used only with a pattern.
    $socketReady = ($tpl.Contains('{{password}}') -and ([string]$sk.loginSuccessPattern).Trim() -and $port -ge 1 -and $port -le 65535 -and [bool](Resolve-SocketHost -SocketHost ([string]$sk.host) -AeosUrl ([string]$cfg.aeosUrl)))
    if ($socketReady) {
        $login = Get-SocketLoginText -Rid $Rid
        if ($login.Error) { return @{ ok = $false; checked = $true; refused = $true; reason = [string]$login.Error } }
        $sess = Invoke-SocketSession -Rid $Rid -What 'login check' -LoginText $login.Text -LoginShown $login.Shown -Commands @()
        if ($sess.fault) { return @{ ok = $false; checked = $true; refused = (([string]$sess.fault) -like 'login rejected*'); reason = [string]$sess.fault } }
        Write-DebugLog $Rid 'Login checked over the socket interface: accepted.'
        return @{ ok = $true; checked = $true; refused = $false; reason = '' }
    }
    $ld = $cfg.actions.listDoors
    if (-not [string]$cfg.aeosUrl -or -not [string]$ld.operation) {
        Write-DebugLog $Rid 'Login not checked: neither the socket login nor the list doors action is set up yet.'
        # Behind the proxy an unchecked login would let anybody in: refused. On the local console the first setup still works.
        if ($script:BehindProxy) {
            return @{ ok = $false; checked = $false; refused = $false; notConfigured = $true; reason = 'AEOS login cannot be checked: set up the AEOS connection on the server first.' }
        }
        return @{ ok = $true; checked = $false; refused = $false; reason = '' }
    }
    $ps = 0
    [void][int]::TryParse([string]$ld.pageSize, [ref]$ps)
    $body = ([string]$ld.body).Replace('{{start}}', '0').Replace('{{pageSize}}', [string]$ps)
    $r = Invoke-SoapCall -Rid $Rid -What 'login check' -SoapAction ([string]$ld.soapAction) -BodyTemplate $body
    # Only an affirmative answer (HTTP 2xx and no SOAP fault) accepts the login: a 500 or a fault is a refusal too.
    if (-not $r.ok) {
        $why = 'AEOS answered HTTP ' + $r.httpStatus + ' to the list doors call.'
        if ($r.fault -and $r.httpStatus -ge 200 -and $r.httpStatus -lt 300) { $why = 'AEOS answered the list doors call with a fault: ' + $r.fault }
        return @{ ok = $false; checked = $true; refused = $true; reason = $why }
    }
    Write-DebugLog $Rid ('Login checked with the list doors call (HTTP ' + $r.httpStatus + '): accepted.')
    return @{ ok = $true; checked = $true; refused = $false; reason = '' }
}

function Set-DoorAliases {
    # Updates is an id -> alias table; an empty alias removes the entry. Everything is checked first, then the config is saved.
    param($Updates)
    $cur = [ordered]@{}
    if ($null -ne $script:Config.aliases) { foreach ($p in $script:Config.aliases.PSObject.Properties) { $cur[$p.Name] = [string]$p.Value } }
    foreach ($k in @($Updates.Keys)) {
        $v = ([string]$Updates[$k]).Trim()
        if (-not $v) { if ($cur.Contains($k)) { $cur.Remove($k) }; continue }
        $e = Test-AliasEntry -Id $k -Alias $v
        if ($e) { throw (New-ApiException 400 'invalid_alias' $e) }
        $cur[$k] = $v
    }
    $script:Config.aliases = [pscustomobject]$cur
    Save-ConfigFile -Config $script:Config -Path $script:ConfigPath
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
        throw (New-ApiException 502 'wsdl_parse' ('The WSDL could not be parsed: ' + (Protect-Text -Text $_.Exception.Message)))
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
    # A socket action reads the state in the same session. After a SOAP action the poller re-reads that door at once.
    if (-not $socket -and $null -ne $script:Shared -and $null -ne $script:Shared.Account -and @(Get-DoorStateChecks).Count -gt 0) {
        $script:Shared.Priority.Enqueue([string]$Id)
    }
    if ($null -ne $caught) { throw $caught }
    if ($socket) {
        $o = @{ ok = $result.ok; transport = 'socket'; httpStatus = 0; fault = $result.fault; reply = $result.reply; response = $result.reply }
        if ($null -ne $result.state) { $o.state = $result.state; $o.stateDetail = $result.stateDetail }
        return $o
    }
    return @{ ok = $result.ok; httpStatus = $result.httpStatus; fault = $result.fault; response = $result.response }
}

function Assert-BatchAllowed {
    # The checks Invoke-DoorBatch makes before it sends anything, so a bad batch is refused by the request itself (400 / 401)
    # and only a good one becomes a background job.
    param([string]$Action, $Doors)
    if (@('lock', 'unlock', 'access', 'normal') -notcontains $Action) { throw (New-ApiException 400 'bad_action' 'Unknown action.') }
    $a = $script:Config.actions.$Action
    if ([string]$a.transport -eq 'socket') {
        if (-not $a.command) { throw (New-ApiException 400 'not_configured' ('The ' + $Action + ' action has no socket command on the Setup tab.')) }
    }
    else {
        if (-not $a.operation) { throw (New-ApiException 400 'not_configured' ('The ' + $Action + ' action is not mapped on the Setup tab.')) }
        Assert-CanCall
    }
    if (@($Doors | Where-Object { $null -ne $_ }).Count -eq 0) { throw (New-ApiException 400 'bad_request' 'Select at least one door.') }
}

function Invoke-DoorBatch {
    # One action on many doors. Socket transport: ONE session (login + init once, the action command of every door,
    # then the state checks of every door). SOAP transport: one call per door in turn. A door with a refused value is
    # reported and not sent; the others go on. One audit record per door, tagged batch:<request id>.
    # -Report (an object with a label) also writes the arming report CSV next to the audit file; the answer names it.
    # -OnProgress (a scriptblock: done, total, phase) is called as the batch advances; the batch job of the page uses it.
    param([string]$Rid, [string]$Action, $Doors, $Report = $null, $OnProgress = $null)
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
    if ($null -ne $OnProgress) { & $OnProgress 0 $list.Count 'Sending' }
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
                if ($null -ne $OnProgress) { & $OnProgress ([Math]::Min($off + $part.Count, $list.Count)) $list.Count 'Sending' }
                continue
            }
            $cmds = @()
            foreach ($row in $part) { $cmds += @{ Text = $row.Text; Shown = $row.Text; Pattern = [string]$a.successPattern; Key = 'action' } }
            $plan = @()
            if ($checks.Count -gt 0) {
                $plan = @(Get-DoorStatePlan -Doors @($part | ForEach-Object { $_.Door }) -Checks $checks)
                $cmds += @(Get-DoorStateCommands -Plan $plan -Checks $checks)
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
            if ($null -ne $OnProgress) { & $OnProgress ([Math]::Min($off + $part.Count + ($list.Count - $send.Count), $list.Count)) $list.Count 'Sending' }
        }
    }
    else {
        $stopWhy = $null
        $sent = 0
        foreach ($row in $rows) {
            $sent++
            if ($null -ne $OnProgress) { & $OnProgress ($sent - 1) $list.Count 'Sending' }
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
        if ($null -ne $OnProgress) { & $OnProgress $list.Count $list.Count 'Reading states' }
        if ($checks.Count -gt 0) {
            try { $states = @((Get-DoorStates -Rid $Rid -Doors @($rows | ForEach-Object { $_.Door })).states) }
            catch {
                $m = $_.Exception.Message
                $states = @($rows | ForEach-Object { @{ id = $_.Id; state = '?'; detail = $m } })
            }
        }
    }
    $okCount = 0
    if ($null -ne $OnProgress) { & $OnProgress $list.Count $list.Count 'Writing the audit' }
    foreach ($row in $rows) {
        if ($row.Ok) { $okCount++ }
        Write-AuditRecord -Action $Action -DoorId $row.Id -DoorName $row.Name -HttpStatus $row.HttpStatus -Ok $row.Ok -Fault $row.Fault -Batch $tag
    }
    Write-DebugLog $Rid ('Audit records written: ' + $rows.Count + ' x action=' + $Action + ' ' + $tag + ' ok=' + $okCount)
    if ($socket -and $null -ne $states) { Update-StateCache -States $states }
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
            $ownerName = ''
            if ($null -ne $script:Cred) { $ownerName = [string]$script:Cred.UserName }
            $reportFile = Write-ArmingReport -Label $lab -Action $Action -Rows $rows -JobId $Rid -Owner $ownerName
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
                throw (New-ApiException 502 'parse_failed' ('The response could not be parsed (page ' + $Page + '): ' + (Protect-Text -Text $_.Exception.Message)))
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
    if ($res.ok) { Set-ServerDoors -Doors @($res.doors) }
    Save-StateCache -MinAgeSec 0
    return @{ ok = $res.ok; httpStatus = $res.httpStatus; fault = $res.fault; doors = @($res.doors); raw = $res.raw; pages = $res.pages; lastKnown = (Get-LastKnownStates -Doors $res.doors) }
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

function Get-AuditSelection {
    # The audit filters of the query string (user, door, action, from, to); a bad date is a 400.
    param($Request, $Records)
    $qs = $Request.QueryString
    foreach ($k in @('from', 'to')) {
        $v = [string]$qs[$k]
        if ($v -and $v -notmatch '^\d{4}-\d\d-\d\d$') { throw (New-ApiException 400 'bad_request' ('The ' + $k + ' date must look like 2026-11-13.')) }
    }
    return (Select-AuditRecords -Records $Records -User ([string]$qs['user']) -Door ([string]$qs['door']) -Action ([string]$qs['action']) -From ([string]$qs['from']) -To ([string]$qs['to']))
}

function Invoke-Route {
    param($Ctx, [string]$Rid)
    $req = $Ctx.Request
    $method = $req.HttpMethod.ToUpperInvariant()
    $path = $req.Url.AbsolutePath
    if (-not $req.IsLocal) { return (New-ErrorResult 403 'forbidden' 'Requests are accepted from this computer only.') }
    if ($method -eq 'GET' -and $path -eq '/') {
        # Behind the proxy the page holds no key before the login: the key of a session comes with GET /api/v1/session.
        $pageKey = ''
        if (-not $script:BehindProxy) { $pageKey = [string]$script:Token }
        $html = $script:PageHtml.Replace('__TOKEN__', $pageKey).Replace('__VERSION__', $script:Version)
        return @{ Status = 200; Bytes = [System.Text.Encoding]::UTF8.GetBytes($html); ContentType = 'text/html; charset=utf-8'
            Headers = @{ 'Content-Security-Policy' = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" } }
    }
    if ($method -eq 'GET' -and $path -eq '/health') {
        return @{ Status = 200; Json = @{ status = 'ok'; version = $script:Version } }
    }
    if (-not $path.StartsWith('/api/v1/')) { return (New-ErrorResult 404 'not_found' 'Not found.') }

    $origin = $req.Headers['Origin']
    $allowedOrigin = 'http://localhost:' + $script:Port
    if ($script:BehindProxy) { $allowedOrigin = [string]$script:PublicOrigin }
    if (-not (Test-OriginAllowed -Origin $origin -Allowed $allowedOrigin)) { return (New-ErrorResult 403 'forbidden' 'Origin not allowed.') }

    # Session: the cookie finds it; the session's own credential and page key are used from here on.
    $cookieId = Get-CookieValue -Header ([string]$req.Headers['Cookie']) -Name 'dk_session'
    $route = $method + ' ' + $path.ToLowerInvariant()
    $found = Find-Session -Id $cookieId -NoTouch:($route -eq 'get /api/v1/doors/states')
    $script:Sess = $found.Session
    if ($null -ne $script:Sess) {
        $script:Cred = $script:Sess.Cred
        if ($script:BehindProxy -and $null -ne $script:RequestClient) { $script:Sess.ClientIp = [string]$script:RequestClient.Ip }
    }
    $open = ($route -eq 'get /api/v1/session' -or $route -eq 'post /api/v1/login')
    if ($cookieId -and $null -eq $script:Sess -and -not $open) {
        # A cookie whose session is gone (idle time-out, 12 h limit, restart): say so and clear the cookie.
        $why = 'Your session ended. Log in again.'
        if ($found.Expired -eq 'idle') { $why = 'Your session ended after ' + (Get-IdleMinutes) + ' minutes without use. Log in again.' }
        $r = New-ErrorResult 401 'session_expired' $why
        $r.Headers = @{ 'Set-Cookie' = (New-SessionCookieHeader -Id '' -Secure ([bool]$script:BehindProxy) -Clear $true) }
        return $r
    }
    if ($script:BehindProxy -and $null -eq $script:Sess -and -not $open) { return (New-ErrorResult 401 'not_logged_in' 'Log in with the AEOS user first.') }
    if ($route -ne 'get /api/v1/session' -and -not ($script:BehindProxy -and $route -eq 'post /api/v1/login')) {
        $expectedKey = ''
        if ($null -ne $script:Sess) { $expectedKey = [string]$script:Sess.Csrf }
        elseif (-not $script:BehindProxy) { $expectedKey = [string]$script:Token }
        if (-not (Test-CsrfToken -Expected $expectedKey -Supplied ([string]$req.Headers['X-Console-Token']))) { return (New-ErrorResult 403 'forbidden' 'Missing or wrong X-Console-Token.') }
    }

    if (Test-AdminOnlyRoute -Method $method -Path $path) { Assert-Admin }

    if ($method -eq 'PUT' -and $path -eq '/api/v1/aliases') {
        $in = Read-RequestJson $req
        if ($null -eq $in -or $null -eq $in.PSObject.Properties['aliases'] -or $in.aliases -isnot [System.Management.Automation.PSCustomObject]) { throw (New-ApiException 400 'bad_request' 'Send {"aliases": {"<door id>": "<alias>"}}.') }
        $upd = [ordered]@{}
        foreach ($p in $in.aliases.PSObject.Properties) { $upd[$p.Name] = $p.Value }
        if ($upd.Count -gt 20000) { throw (New-ApiException 413 'too_large' 'More than 20000 aliases in one request.') }
        foreach ($k in @($upd.Keys)) { if ($upd[$k] -isnot [string]) { throw (New-ApiException 400 'invalid_alias' ('aliases["' + $k + '"] must be text.')) } }
        Set-DoorAliases -Updates $upd
        Write-DebugLog $Rid ('Aliases saved: ' + $upd.Count + ' entr(ies) changed.')
        return @{ Status = 200; Json = @{ ok = $true; changed = $upd.Count } }
    }
    if ($method -eq 'PUT' -and $path.StartsWith('/api/v1/aliases/')) {
        $raw = $req.RawUrl
        $qi = $raw.IndexOf('?')
        if ($qi -ge 0) { $raw = $raw.Substring(0, $qi) }
        $id = ''
        try { $id = [Uri]::UnescapeDataString($raw.Substring('/api/v1/aliases/'.Length)) } catch { $id = '' }
        $in = Read-RequestJson $req
        if (-not $id -or $null -eq $in -or $null -eq $in.PSObject.Properties['alias'] -or $in.alias -isnot [string]) { throw (New-ApiException 400 'bad_request' 'Send {"alias": "<text>"} to /api/v1/aliases/<door id>.') }
        Set-DoorAliases -Updates ([ordered]@{ $id = $in.alias })
        Write-DebugLog $Rid ('Alias of door ' + $id + ' saved.')
        return @{ Status = 200; Json = @{ ok = $true; id = $id; alias = ([string]$in.alias).Trim() } }
    }

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
            $adminErr = Test-AdminListChange -Old @(Get-AdminList) -New @($merged.access.admins) -User (Get-CurrentUserName)
            if ($adminErr) { throw (New-ApiException 400 'admin_list' $adminErr) }
            # The audit file may not change while a batch job is appending to it.
            $newAuditPath = Resolve-DataPath -Value ([string]$merged.auditFile) -BaseDir $script:ScriptDir -DefaultName 'doorkeeper-audit.jsonl'
            if ($newAuditPath -ne $script:AuditPath) {
                foreach ($aj in @($script:Jobs.Values)) { if (Test-JobActive -Job $aj) { throw (New-ApiException 409 'job_running' 'A batch job is running: the audit file cannot be changed until it has finished.') } }
            }
            $targetChanges = @(Get-AeosTargetChanges -Old $script:Config -New $merged)
            Save-ConfigFile -Config $merged -Path $script:ConfigPath
            $script:Config = $merged
            # The server password may only be used against the address and TLS setting it was entered for.
            if ($targetChanges.Count -gt 0 -and ($null -ne $script:ServerAccount -and $script:ServerAccount.present -or ($null -ne $script:Shared -and $null -ne $script:Shared.Account))) {
                Remove-ServerAccountFiles -BlobPath $script:ServerAccountPath -MetaPath $script:ServerAccountMetaPath
                $script:ServerAccount = Read-ServerAccount -BlobPath $script:ServerAccountPath -MetaPath $script:ServerAccountMetaPath
                Set-PollerAccount -Cred $null
                Write-AuditRecord -Action 'server-account-remove' -DoorId '' -DoorName ($targetChanges -join ',') -HttpStatus 0 -Ok $true -Fault 'AEOS address or TLS setting changed'
                Write-DebugLog $Rid ('Server account removed: AEOS address or TLS setting changed (' + ($targetChanges -join ', ') + ').')
            }
            if ($null -ne $script:Shared) { $script:Shared.Config = $merged; $script:Shared.RelistDoors = $true; $script:Shared.Wake = $true }
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
            if ($u.Length -gt 200) { throw (New-ApiException 400 'bad_login' 'The user name is too long.') }
            $clientIp = [string]$script:RequestClient.Ip
            # 5 failed logins in 5 minutes block that user + client address pair for 5 minutes (audited).
            $lkey = Get-LoginKey -User $u -ClientIp $clientIp
            if ($null -eq $script:LoginAttempts) { $script:LoginAttempts = @{} }
            $entry = $script:LoginAttempts[$lkey]
            $wait = Get-LoginBlockSeconds -Entry $entry -Now ([DateTime]::UtcNow)
            if ($wait -gt 0) {
                Write-AuditRecord -Action 'login-blocked' -DoorId '' -DoorName '' -HttpStatus 429 -Ok $false -Fault ('Too many failed logins; blocked for ' + $wait + ' more seconds.') -AeosUser $u
                Write-DebugLog $Rid ('Login blocked: user=' + $u + ' from ' + $clientIp + ' for ' + $wait + ' s')
                throw (New-ApiException 429 'login_blocked' ('Too many failed logins for this user from this address. Try again in ' + $wait + ' seconds.'))
            }
            $ss = New-Object System.Security.SecureString
            foreach ($ch in $p.ToCharArray()) { $ss.AppendChar($ch) }
            $ss.MakeReadOnly()
            # The password is checked against AEOS first; a refused login keeps nothing and is audited.
            $prevCred = $script:Cred
            $newCred = New-Object System.Management.Automation.PSCredential($u, $ss)
            $script:Cred = $newCred
            $chk = $null
            $caught = $null
            try { $chk = Test-AeosLogin -Rid $Rid }
            catch { $caught = $_.Exception }
            $why = ''
            if ($null -ne $caught) { $why = $caught.Message }
            elseif (-not $chk.ok) { $why = [string]$chk.reason }
            $why = Protect-Text -Text $why
            if ($why) {
                $script:Cred = $prevCred
                $blockNow = $false
                if ($null -eq $caught -and $chk.refused) {
                    if ($null -eq $entry) { $entry = New-LoginAttemptEntry; $script:LoginAttempts[$lkey] = $entry }
                    $blockNow = Register-LoginFailure -Entry $entry -Now ([DateTime]::UtcNow)
                }
                $auditWhy = $why
                if ($blockNow) { $auditWhy = $why + ' (5 failed logins in 5 minutes: this user from this address is blocked for 5 minutes)' }
                Write-AuditRecord -Action 'login' -DoorId '' -DoorName '' -HttpStatus 0 -Ok $false -Fault $auditWhy -AeosUser $u
                Write-DebugLog $Rid ('Login refused: user=' + $u + ' - ' + $auditWhy)
                if ($null -ne $caught) { throw $caught }
                if ($chk.notConfigured) { throw (New-ApiException 503 'not_configured' ([string]$chk.reason)) }
                if ($chk.refused) { throw (New-ApiException 401 'login_refused' 'AEOS refused the user or password.') }
                throw (New-ApiException 502 'login_check_failed' ('The login could not be checked: ' + $why))
            }
            if ($script:LoginAttempts.ContainsKey($lkey)) { $script:LoginAttempts.Remove($lkey) }
            # A new login replaces the session of this browser (if any); the old credential is dropped.
            if ($null -ne $script:Sess) { $script:Sessions.Remove([string]$script:Sess.Id) }
            $sess = New-SessionRecord -Cred $newCred -ClientIp $clientIp -WindowsUser ([string]$script:RequestClient.WindowsUser)
            $script:Sessions[$sess.Id] = $sess
            $script:Sess = $sess
            $script:Cred = $newCred
            Write-AuditRecord -Action 'login' -DoorId '' -DoorName '' -HttpStatus 0 -Ok $true -Fault $null
            Write-DebugLog $Rid ('Login: user=' + $u)
            return @{ Status = 200; Json = (Get-SessionInfo); Headers = @{ 'Set-Cookie' = (New-SessionCookieHeader -Id $sess.Id -Secure ([bool]$script:BehindProxy)) } }
        }
        'POST /api/v1/logout' {
            Write-DebugLog $Rid 'Logout'
            if ($null -ne $script:Cred) { Write-AuditRecord -Action 'logout' -DoorId '' -DoorName '' -HttpStatus 0 -Ok $true -Fault $null }
            if ($null -ne $script:Sess) { $script:Sessions.Remove([string]$script:Sess.Id) }
            $script:Sess = $null
            $script:Cred = $null
            return @{ Status = 200; Json = (Get-SessionInfo); Headers = @{ 'Set-Cookie' = (New-SessionCookieHeader -Id '' -Secure ([bool]$script:BehindProxy) -Clear $true) } }
        }
        'GET /api/v1/session' {
            $info = Get-SessionInfo
            if ($null -ne $found -and $found.Expired) { $info.expired = [string]$found.Expired }
            return @{ Status = 200; Json = $info }
        }
        'GET /api/v1/server-account' {
            return @{ Status = 200; Json = (Get-ServerAccountStatus) }
        }
        'PUT /api/v1/server-account' {
            $in = Read-RequestJson $req
            $u = ''
            $p = ''
            if ($null -ne $in) { $u = [string]$in.user; $p = [string]$in.password }
            if (-not $u.Trim() -or -not $p) { throw (New-ApiException 400 'bad_request' 'The server account needs a user name and a password.') }
            $u = $u.Trim()
            if ($u.Length -gt 200 -or $u -match '[\x00-\x1F\x7F]') { throw (New-ApiException 400 'bad_request' 'The user name is too long or has a control character.') }
            $ss = New-Object System.Security.SecureString
            foreach ($ch in $p.ToCharArray()) { $ss.AppendChar($ch) }
            $ss.MakeReadOnly()
            $acct = New-Object System.Management.Automation.PSCredential($u, $ss)
            # AEOS must accept the account before it is kept (the admin's own credential is put back afterwards).
            $adminCred = $script:Cred
            $script:Cred = $acct
            $chk = $null
            $caught = $null
            try { $chk = Test-AeosLogin -Rid $Rid }
            catch { $caught = $_.Exception; $caughtText = Protect-Text -Text $_.Exception.Message }
            finally { $script:Cred = $adminCred }
            if ($null -ne $caught) { throw (New-ApiException 502 'login_check_failed' ('The server account could not be checked: ' + $caughtText)) }
            if (-not $chk.ok) {
                if ($chk.notConfigured) { throw (New-ApiException 503 'not_configured' ([string]$chk.reason)) }
                if ($chk.refused) { throw (New-ApiException 401 'login_refused' 'AEOS refused the server account user or password. It was not saved.') }
                throw (New-ApiException 502 'login_check_failed' ('The server account could not be checked: ' + [string]$chk.reason))
            }
            try { $saved = Save-ServerAccount -Cred $acct -SetBy (Get-CurrentUserName) -BlobPath $script:ServerAccountPath -MetaPath $script:ServerAccountMetaPath }
            catch { throw (New-ApiException 500 'store_failed' ('The server account could not be stored: ' + $_.Exception.Message + ' (behind IIS the app pool needs loadUserProfile=true).')) }
            if ($saved.aclError) { Write-DebugLog $Rid ('Server account file ACL not set: ' + $saved.aclError) 'WARN' }
            $script:ServerAccount = Read-ServerAccount -BlobPath $script:ServerAccountPath -MetaPath $script:ServerAccountMetaPath
            Write-AuditRecord -Action 'server-account-set' -DoorId '' -DoorName $u -HttpStatus 0 -Ok $true -Fault $null
            Write-DebugLog $Rid ('Server account set by ' + (Get-CurrentUserName) + ' (user ' + $u + ').')
            Set-PollerAccount -Cred $acct
            Start-StatePoller
            return @{ Status = 200; Json = (Get-ServerAccountStatus) }
        }
        'DELETE /api/v1/server-account' {
            Remove-ServerAccountFiles -BlobPath $script:ServerAccountPath -MetaPath $script:ServerAccountMetaPath
            $script:ServerAccount = Read-ServerAccount -BlobPath $script:ServerAccountPath -MetaPath $script:ServerAccountMetaPath
            Set-PollerAccount -Cred $null
            Write-AuditRecord -Action 'server-account-remove' -DoorId '' -DoorName '' -HttpStatus 0 -Ok $true -Fault $null
            Write-DebugLog $Rid ('Server account removed by ' + (Get-CurrentUserName) + '.')
            return @{ Status = 200; Json = (Get-ServerAccountStatus) }
        }
        'GET /api/v1/doors/states' {
            $since = 0
            $q = $req.QueryString['since']
            if ($q -and -not [int]::TryParse($q, [ref]$since)) { throw (New-ApiException 400 'bad_request' 'since must be a whole number.') }
            $ps = Get-PollSettings
            $ans = Get-StateAnswer -Since $since -Allowed $(if ($null -ne $script:Sess) { $script:Sess.DoorIds } else { $null })
            return @{ Status = 200; Json = @{ ver = $ans.ver; live = (Test-LiveStates); account = (Test-ServerAccountSet); freshSeconds = $ps.freshSeconds; pollSeconds = $ps.pollSeconds; states = $ans.states } }
        }        'GET /api/v1/me/settings' {
            if ($null -eq $script:Cred) { throw (New-ApiException 401 'not_logged_in' 'Log in with the AEOS user first.') }
            return @{ Status = 200; Json = @{ user = (Get-CurrentUserName); settings = (Get-UserSettings -User (Get-CurrentUserName)) } }
        }
        'PUT /api/v1/me/settings' {
            if ($null -eq $script:Cred) { throw (New-ApiException 401 'not_logged_in' 'Log in with the AEOS user first.') }
            $text = Read-RequestText $req 4096
            $in = $null
            try { $in = ConvertFrom-Json -InputObject $text } catch { throw (New-ApiException 400 'bad_json' 'The request body is not valid JSON.') }
            $cv = ConvertTo-UserSettings -In $in
            if (-not $cv.ok) { throw (New-ApiException 400 'bad_settings' $cv.error) }
            Set-UserSettings -User (Get-CurrentUserName) -Value $cv.value
            return @{ Status = 200; Json = @{ ok = $true; settings = $cv.value } }
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
            $dl = Get-DoorsFromServer -Rid $Rid
            $ps = Get-PollSettings
            $dl.live = (Test-LiveStates)
            $dl.account = (Test-ServerAccountSet)
            # the doors this session may see (its own listing) - the states and the door routes are limited to them
            if ($null -ne $script:Sess -and $dl.ok) {
                $idset = @{}
                foreach ($dd0 in @($dl.doors)) { $idset[[string]$dd0.id] = $true }
                $script:Sess.DoorIds = $idset
            }
            $dl.freshSeconds = $ps.freshSeconds
            $dl.ver = (Get-StateVersion)
            return @{ Status = 200; Json = $dl }
        }
        'POST /api/v1/doors/action' {
            Assert-Licensed
            $in = Read-RequestJson $req
            if ($null -eq $in) { throw (New-ApiException 400 'bad_request' 'Empty request body.') }
            # Only the id of the client counts: name and extra come from the server's own door list (also for the audit line).
            $dd = @(Resolve-ServerDoors -Requested @([string]$in.id) -Map $script:Shared.DoorMap -Allowed $(if ($null -ne $script:Sess) { $script:Sess.DoorIds } else { $null }))
            return @{ Status = 200; Json = (Invoke-DoorAction -Rid $Rid -Action ([string]$in.action) -Id ([string]$dd[0].id) -Name ([string]$dd[0].name) -Extra $dd[0].extra) }
        }
        'POST /api/v1/doors/state' {
            $in = Read-RequestJson $req
            if ($null -eq $in -or $null -eq $in.doors) { throw (New-ApiException 400 'bad_request' 'A list of doors is required.') }
            # one id once; at most "Doors per socket session" in one request (a bigger read belongs to the poller / chunks)
            $seenIds = @{}
            $idList = @()
            foreach ($rq in @($in.doors)) {
                if ($null -eq $rq) { continue }
                $rid0 = ''
                if ($rq -is [string]) { $rid0 = $rq } elseif ($null -ne $rq.PSObject.Properties['id']) { $rid0 = [string]$rq.id }
                if ($rid0 -and -not $seenIds.ContainsKey($rid0)) { $seenIds[$rid0] = $true; $idList += $rid0 }
            }
            if ($idList.Count -gt (Get-MaxDoorsPerRefresh)) { throw (New-ApiException 400 'too_many' ('At most ' + (Get-MaxDoorsPerRefresh) + ' doors in one state request.')) }
            $dd = @(Resolve-ServerDoors -Requested $idList -Map $script:Shared.DoorMap -Allowed $(if ($null -ne $script:Sess) { $script:Sess.DoorIds } else { $null }))
            if (Test-LiveStates) {
                # live: answer from the cache and let the poller re-read these doors; the request loop never waits for AEOS here
                foreach ($qd in $dd) { if ($script:Shared.Priority.Count -lt 5000) { $script:Shared.Priority.Enqueue([string]$qd.id) } }
                return @{ Status = 200; Json = @{ states = @(Get-CachedStates -Ids $idList); cached = $true } }
            }
            return @{ Status = 200; Json = (Get-DoorStates -Rid $Rid -Doors $dd) }
        }
        'POST /api/v1/doors/batch' {
            Assert-Licensed
            $in = Read-RequestJson $req
            if ($null -eq $in -or $null -eq $in.doors) { throw (New-ApiException 400 'bad_request' 'An action and a list of doors are required.') }
            # The batch runs as a background job with the operator's own credential; the page follows GET /api/v1/jobs/<id>.
            Assert-BatchAllowed -Action ([string]$in.action) -Doors @($in.doors)
            $me = Get-CurrentUserName
            $busy = Find-ActiveJobOfUser -Jobs $script:Jobs -User $me
            if ($null -ne $busy) { throw (New-ApiException 409 'job_running' 'You already have a job running. Wait until it has finished.') }
            $doorList = @(Resolve-ServerDoors -Requested @($in.doors) -Map $script:Shared.DoorMap -Allowed $(if ($null -ne $script:Sess) { $script:Sess.DoorIds } else { $null }))
            $job = New-JobRecord -Id $Rid -User $me -Action ([string]$in.action) -Total $doorList.Count
            $script:Jobs[$Rid] = $job
            Start-BatchJob -Job $job -Doors $doorList -Report $in.report -Cred $script:Cred -Client @{ Ip = [string]$script:RequestClient.Ip; WindowsUser = $script:RequestClient.WindowsUser }
            Write-DebugLog $Rid ('Batch job started: ' + [string]$in.action + ' on ' + $doorList.Count + ' door(s) for ' + $me)
            return @{ Status = 202; Json = @{ jobId = $Rid; state = 'queued'; total = $doorList.Count; action = [string]$in.action } }
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
            $sel = @(Get-AuditSelection -Request $req -Records $recs)
            $last = @($sel | Select-Object -Last $limit)
            return @{ Status = 200; Json = @{ records = $last; chainOk = $chain.ChainOk; badIndex = $chain.BadIndex; total = $recs.Count; matched = $sel.Count } }
        }
        'GET /api/v1/audit/export' {
            $recs = @(Read-AuditRecords)
            $sel = @(Get-AuditSelection -Request $req -Records $recs)
            $name = 'doorkeeper-audit-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.csv'
            return @{ Status = 200; Bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((ConvertTo-AuditCsv -Records $sel)); ContentType = 'text/csv; charset=utf-8'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="' + $name + '"' } }
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
            if ($f -notmatch '^doorkeeper-arming-\d{8}-\d{6}(-[0-9a-f]{8})?(-\d+)?\.csv$') { throw (New-ApiException 400 'bad_request' 'Bad file name.') }
            # Owner or admin only (like a job); a report with no remembered owner (older file, restart) is for admins.
            $meR = Get-CurrentUserName
            $ownerR = ''
            if ($null -ne $script:Shared -and $null -ne $script:Shared.ReportOwners -and $script:Shared.ReportOwners.ContainsKey($f)) { $ownerR = [string]$script:Shared.ReportOwners[$f] }
            $isOwnerR = ($ownerR -and [string]::Equals($ownerR, $meR, [System.StringComparison]::OrdinalIgnoreCase))
            if (-not $isOwnerR -and (Get-UserRole -Admins @(Get-AdminList) -User $meR -BehindProxy:([bool]$script:BehindProxy)) -ne 'admin') { throw (New-ApiException 403 'forbidden_role' 'This report belongs to another operator.') }
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
        default {
            if ($method -eq 'GET' -and $path.StartsWith('/api/v1/jobs/')) {
                $jid = $path.Substring('/api/v1/jobs/'.Length)
                if ($jid -notmatch '^[0-9a-f]{8}$' -or -not $script:Jobs.ContainsKey($jid)) { throw (New-ApiException 404 'not_found' 'No such job.') }
                $job = $script:Jobs[$jid]
                $me = Get-CurrentUserName
                $isMine = [string]::Equals([string]$job.User, $me, [System.StringComparison]::OrdinalIgnoreCase)
                if (-not $isMine -and (Get-UserRole -Admins @(Get-AdminList) -User $me -BehindProxy:([bool]$script:BehindProxy)) -ne 'admin') { throw (New-ApiException 403 'forbidden_role' 'This job belongs to another operator.') }
                return @{ Status = 200; Json = (Get-JobPublic -Job $job) }
            }
            return (New-ErrorResult 404 'not_found' 'Unknown API path or method.')
        }
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
    $resp.Headers.Add('Referrer-Policy', 'no-referrer')
    $own = @{}
    if ($Result.ContainsKey('Headers')) { foreach ($k in $Result.Headers.Keys) { $own[([string]$k).ToLowerInvariant()] = $true } }
    # Content-Security-Policy on every answer: the page sets its own (self only); everything else may load nothing.
    if (-not $own.ContainsKey('content-security-policy')) { $resp.Headers.Add('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'") }
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
    $quiet = (($method -eq 'GET' -and $path -eq '/api/v1/debuglog') -or ($method -eq 'GET' -and $path -eq '/api/v1/doors/states'))
    $result = $null
    $errNote = ''
    # The request context: who asked (session credential, client address, Windows user from IIS). Cleared at the end.
    $script:Cred = $null
    $script:Sess = $null
    $remote = ''
    try { $remote = $Ctx.Request.RemoteEndPoint.Address.ToString() } catch { }
    # Behind IIS the Windows user is not available (LOGON_USER is empty at the URL Rewrite stage, lab-proven): windowsUser stays empty.
    $winUser = $null
    if ($script:BehindProxy) { $winUser = '' }
    $script:RequestClient = @{ Ip = (Get-ForwardedClientIp -RemoteAddr $remote -ForwardedFor ([string]$Ctx.Request.Headers['X-DK-Client-IP']) -BehindProxy ([bool]$script:BehindProxy)); WindowsUser = $winUser }
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
    $script:Cred = $null
    $script:Sess = $null
    $script:RequestClient = $null
    try { Send-Result -Ctx $Ctx -Result $result -Rid $rid }
    catch { Write-DebugLog $rid ('Sending the response failed: ' + $_.Exception.Message) 'ERROR' }
    $sw.Stop()
    try { Save-StateCache } catch { }
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
#doors-body td.dname{font-weight:600;color:var(--ink)}
nav button.admin-tab{display:none}
body.role-admin nav button.admin-tab{display:inline-block}
th.sortable{cursor:pointer;user-select:none;white-space:nowrap}
th.sortable:hover{color:var(--ink)}
td.alias{min-width:110px}
td.alias.editable{cursor:text}
td.alias.editable:hover{outline:1px dashed var(--field);outline-offset:-2px}
input.alias-edit{width:100%;min-width:120px;height:30px}
.schip.last{opacity:.55;font-weight:600}
.aud-filter{display:flex;flex-wrap:wrap;align-items:flex-end;gap:8px;margin:8px 0}
tr.picked{background:#F3F7FF}
button{font:inherit;cursor:pointer;height:36px;padding:0 14px;background:#fff;color:var(--ink);border:1px solid var(--field);border-radius:6px}
button:hover{filter:brightness(.96)}
button.primary{background:var(--blue-deep);color:#fff;border:none;font-weight:600;height:40px;padding:0 16px}
button.act{margin-right:6px;height:30px;padding:0 10px;font-size:13px}
.pager{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:8px 0;font-size:13px}
.pager button{height:30px;padding:0 10px;font-size:13px}
.pager select{height:30px;padding:0 6px;font-size:13px}
.pager label{display:inline-flex;align-items:center;gap:6px;margin:0}
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
  <button class="tab admin-tab" data-tab="setup">Setup</button>
  <button class="tab admin-tab" data-tab="raw">Raw call</button>
  <button class="tab admin-tab" data-tab="audit">Audit</button>
  <button class="tab admin-tab" data-tab="debug">Debug</button>
</nav>

<div class="panel active" id="tab-doors">
  <div class="toolbar">
    <button id="btn-load-doors" class="primary">Load doors</button>
    <button id="btn-refresh-state" style="display:none"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.64-6.36"></path><polyline points="21 3 21 9 15 9"></polyline></svg>Refresh state</button>
    <input type="text" id="door-filter" placeholder="Filter doors">
    <span id="door-counts"></span>
  </div>
  <div class="msg" id="doors-msg"></div>
  <div id="job-bar" style="display:none"><span id="job-text"></span> <progress id="job-progress" value="0" max="1"></progress></div>
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
    <p class="hint" id="target-hint">Changing the AEOS address or TLS setting removes the server account; enter it again afterwards.</p>
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
    <label><span>Login success pattern (regex on the reply line)</span><input type="text" id="sk-loginSuccessPattern" size="30"></label> <span id="sk-pattern-warn" class="warn" style="display:none">Empty = the login is not checked over the socket.</span>
    <label style="display:block"><span>Init commands (one per line, each sent after the login; one reply line is read for each)</span><textarea id="sk-initCommands" style="min-height:44px"></textarea></label>
  </fieldset>
  <fieldset id="fs-access"><legend>Admins</legend>
    <p class="hint">AEOS user names (one per line, upper or lower case) that may use the Setup, Raw call, Audit and Debug tabs. Every other user is an operator and sees the Doors tab only. While this list is empty, every user is an admin. Your own name must stay in the list.</p>
    <label style="display:block"><span>Admins (AEOS user names, one per line)</span><textarea id="cfg-admins" style="min-height:60px"></textarea></label>
  </fieldset>
  <fieldset id="fs-server"><legend>Live door states (server account)</legend>
    <p class="hint">The console reads all door states in the background with its own AEOS account, so every operator sees them live without pressing Load. The account only reads: every door action runs with the operator's own AEOS account. Use a dedicated AEOS user with the fewest rights that allow login and the state queries. The password is stored encrypted for the Windows account that runs DoorKeeper and is never shown again.</p>
    <div id="sa-status" class="hint">Status unknown.</div>
    <label><span>Server account (AEOS user)</span><input type="text" id="sa-user" size="24" autocomplete="off"></label>
    <label><span>Password</span><input type="password" id="sa-password" size="24" autocomplete="new-password"></label>
    <button id="btn-sa-save" type="button">Set server account</button>
    <button id="btn-sa-remove" type="button">Remove</button>
    <div class="msg" id="sa-msg"></div>
    <label><span>Pause between read rounds (s)</span><input type="number" id="cfg-pollSeconds" min="1" max="3600" style="width:90px"></label>
    <label><span>A state counts as fresh for (s)</span><input type="number" id="cfg-freshSeconds" min="5" max="86400" style="width:90px"></label>
    <label><span>Log out after idle minutes</span><input type="number" id="cfg-idleMinutes" min="1" max="720" style="width:90px"></label>
  </fieldset>
  <fieldset id="fs-aliases"><legend>Aliases</legend>
    <p class="hint">An alias is a friendly name for a door (shown in the Alias column of the Doors tab). Export the doors as CSV (id;name;alias), fill in the alias column, import it back. The first column may also be the door name when the id is not known. An empty alias removes the entry. A single alias can also be edited in the Doors table (click the Alias cell).</p>
    <p><button id="btn-alias-export" type="button">Export doors as CSV</button>
    <label><span>CSV file (id;alias)</span><input type="file" id="alias-file" accept=".csv,text/csv,text/plain"></label>
    <button id="btn-alias-import" type="button">Import aliases</button></p>
    <div class="msg" id="alias-msg"></div>
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
  <div class="aud-filter">
    <label><span>AEOS or Windows user</span><input type="text" id="aud-user" size="14"></label>
    <label><span>Door (name, alias or id)</span><input type="text" id="aud-door" size="18"></label>
    <label><span>Action</span><select id="aud-action"><option value="all">All</option><option value="opened">Opened (unlock or access)</option><option value="lock">lock</option><option value="unlock">unlock</option><option value="access">access</option><option value="normal">normal</option><option value="login">login</option><option value="logout">logout</option><option value="raw-socket">raw-socket</option></select></label>
    <label><span>From (UTC date)</span><input type="date" id="aud-from"></label>
    <label><span>To (UTC date)</span><input type="date" id="aud-to"></label>
    <button id="btn-audit-refresh">Refresh</button>
    <button id="btn-audit-export" type="button">Export CSV</button>
  </div>
  <span id="audit-chain"></span> <span id="audit-count"></span>
  <div class="msg" id="audit-msg"></div>
  <table><thead><tr><th>Time (UTC)</th><th>Computer</th><th>Windows user</th><th>AEOS user</th><th>Action</th><th>Door</th><th>Alias</th><th>HTTP</th><th>OK</th><th>Fault</th></tr></thead>
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
var ANON=TOKEN;
/* The page key: the key of the session once logged in (X-Console-Token), else the one the page came with (empty behind the proxy). The meta tag follows. */
function setToken(t){TOKEN=t||ANON;var m=document.querySelector('meta[name="console-token"]');if(m){m.setAttribute('content',TOKEN);}}
var ACTIONS=['listDoors','lock','unlock','access','normal'];
var DOOR_ACTIONS=['lock','unlock','access','normal'];
var CFG=null,LIC=null,OPS=[],DOORS=[],debugTimer=null,SEL={},STATES={},RES={},BATCH_BUSY=false,DS_ROWS=4;
var PLACE={},NODES={},TREE_DOORS=null,TREE_LOC='',LOCFILTER='',ARMREP=null;
/* Session and role (the server decides; the page only hides), fresh and last-known door states, sort, per-user settings */
var SESSION=null,FRESH={},LAST={},SORT={col:'',dir:''},READGEN=0,ME_TIMER=null,ME_APPLYING=false,STATE_CHUNK=100;
/* Live states (server account): ACCT = the server reads the states with its own account (freshness then always expires), LIVE = that read works right now. The page asks for the changes since its last version every 3 s, with a back-off while it fails. FRESH[id] is true (read by this page, no server account) or the time (ms) until the state counts as fresh. */
var LIVE=false,VER=0,FRESHSEC=120,POLL_TIMER=null,POLL_BUSY=false,SA_TIMER=null,FRESH_TIMER=null,TIMED=false,ACCT=false,POLL_DELAY=3000,POLL_GEN=0,SESSGEN=0;
/* Doors table pager: PAGESIZE 0 = all rows; kept per browser (the page works without storage) */
var PAGE_SIZES=[25,50,100,250,500,0],PAGE=1,PAGEKEY='',PAGEROWS=[];
function storedPageSize(){try{var v=parseInt(localStorage.getItem('dk-rows-per-page'),10);if(PAGE_SIZES.indexOf(v)>=0){return v;}}catch(e){}return 100;}
var PAGESIZE=storedPageSize();
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
  var gen=SESSGEN;
  if(body!==undefined){opt.headers['Content-Type']='application/json';opt.body=rawText?body:JSON.stringify(body);}
  return fetch(path,opt).then(function(r){
    return r.text().then(function(txt){
      /* an answer for a session that has ended since the request left is dropped (no data of the last user reaches the page) */
      if(gen!==SESSGEN){var ce=new Error('The session ended.');ce.cancelled=true;ce.rid='-';throw ce;}
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
        er.rid=rid;er.code=(j&&j.error&&j.error.code)||'';
        if(r.status===401&&er.code==='session_expired'){sessionLost(msg);}
        throw er;
      }
      j=j||{};j._rid=rid;return j;
    });
  },function(e){var er=new Error('Cannot reach the console process: '+e.message);er.rid='-';throw er;});
}
function errText(e){return e.cancelled?'':(e.message+' (request id '+(e.rid||'-')+')');}
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
  if(!isAdmin()&&name!=='doors'){name='doors';}
  Array.prototype.forEach.call(document.querySelectorAll('.tab'),function(b){b.classList.toggle('active',b.getAttribute('data-tab')===name);});
  Array.prototype.forEach.call(document.querySelectorAll('.panel'),function(p){p.classList.toggle('active',p.id==='tab-'+name);});
  if(debugTimer){clearInterval(debugTimer);debugTimer=null;}
  if(name==='audit'){loadAudit();}
  if(SA_TIMER){clearInterval(SA_TIMER);SA_TIMER=null;}
  if(name==='setup'){loadServerAccount();SA_TIMER=setInterval(loadServerAccount,4000);}
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
  if(SESSION&&SESSION.noAdmins){
    if(SESSION.behindProxy){b.appendChild(h('div',{class:'err',id:'admin-banner',text:'No admin is set. An administrator of the server must add AEOS user names to access.admins in the DoorKeeper config file and restart the site.'}));}
    else{b.appendChild(h('div',{class:'err',id:'admin-banner',text:'No admin is set: every user can change settings. Add admins on the Setup tab.'}));}
  }
  if(LIC&&!LIC.actionsAllowed){
    var hostTxt=LIC.aeosHost?(' AEOS host to send to your supplier: '+LIC.aeosHost+'.'):'';
    b.appendChild(h('div',{class:'err',id:'lic-banner',text:'Door actions are switched off. '+LIC.reason+hostTxt}));
  }
  $('aeos-url').textContent=(CFG&&CFG.aeosUrl)?CFG.aeosUrl:(CFG?'(AEOS URL not set - open Setup)':'');
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
function isAdmin(){return !!SESSION&&SESSION.role==='admin';}
function loggedIn(){return !!SESSION&&!!SESSION.loggedIn;}
function renderSession(s){
  SESSION=s;setToken(s.csrf);
  $('login-box').style.display=s.loggedIn?'none':'';
  $('logout-box').style.display=s.loggedIn?'':'none';
  $('login-state').textContent=s.loggedIn?('logged in as '+s.user+(s.role==='admin'?' (admin)':'')):'';
  $('btn-load-doors').disabled=!s.loggedIn;$('btn-load-doors').title=s.loggedIn?'':'Log in with an AEOS user first.';
  document.body.classList.toggle('role-admin',isAdmin());
  var act=document.querySelector('.tab.active');
  if(act&&!isAdmin()&&act.getAttribute('data-tab')!=='doors'){showTab('doors');}
  renderBanners();renderDoors();
}
/* The config and the license need a session behind the proxy, so they load after the login (without the proxy, at the start). */
function loadAll(){
  return api('GET','/api/v1/config').then(function(c){
    CFG=c;fillSetup();renderBanners();renderDoors();return loadLicense();
  });
}
/* Nothing of the last user stays on the page. */
function clearView(){
  stopPolling();LIVE=false;ACCT=false;READGEN++;if(FRESH_TIMER){clearInterval(FRESH_TIMER);FRESH_TIMER=null;}
  DOORS=[];SEL={};STATES={};FRESH={};LAST={};RES={};PAGE=1;ARMREP=null;BATCH_BUSY=false;
  $('arm-report').style.display='none';$('job-bar').style.display='none';
  if(SESSION&&SESSION.behindProxy){CFG=null;LIC=null;}
  renderDoors();
}
/* Audit, debug, raw call results, diagnostics, reports and every pending answer of the last user leave the page. */
function clearAdminData(){
  SESSGEN++;
  if(debugTimer){clearInterval(debugTimer);debugTimer=null;}
  if(SA_TIMER){clearInterval(SA_TIMER);SA_TIMER=null;}
  ['audit-body','debug-out','raw-out','raw-socket-out','test-list-out','diag-out','arm-report-failed'].forEach(function(id){var e=$(id);if(e){e.textContent='';}});
  ['audit-chain','audit-count','audit-msg','debug-msg','debug-file','raw-msg','raw-socket-msg','sa-msg','setup-msg','lic-msg','alias-msg','wsdl-status','doors-msg'].forEach(function(id){var e=$(id);if(e){e.textContent='';}});
  $('sa-status').textContent='';$('sa-user').value='';$('sa-password').value='';$('raw-socket-cmd').value='';
  ARMREP=null;$('arm-report').style.display='none';$('job-bar').style.display='none';
  showTab('doors');
}
function sessionLost(msg){
  var bp=!!(SESSION&&SESSION.behindProxy),na=!!(SESSION&&SESSION.noAdmins);
  clearAdminData();
  SESSION={loggedIn:false,user:'',role:'operator',noAdmins:na,behindProxy:bp,csrf:''};
  clearView();renderSession(SESSION);$('login-msg').textContent=msg||'Your session ended. Log in again.';
}
/* per-user settings (server side, per AEOS user): rows per page, sort, filter text, selected tree node */
function applyMe(s){
  if(!s){return;}
  ME_APPLYING=true;
  if(PAGE_SIZES.indexOf(s.rows)>=0){PAGESIZE=s.rows;}
  SORT=s.sortCol?{col:s.sortCol,dir:(s.sortDir==='desc'?'desc':'asc')}:{col:'',dir:''};
  $('door-filter').value=s.filter||'';
  LOCFILTER=s.node||'';
  PAGE=1;PAGEKEY='';
  ME_APPLYING=false;
  renderDoors();
}
function loadMe(){
  if(!loggedIn()){return Promise.resolve();}
  return api('GET','/api/v1/me/settings').then(function(r){applyMe(r.settings);}).catch(function(){});
}
function meBody(){return {rows:PAGESIZE,sortCol:SORT.col,sortDir:SORT.dir,filter:$('door-filter').value.slice(0,200),node:LOCFILTER};}
function saveMe(now){
  if(!loggedIn()||ME_APPLYING){return Promise.resolve();}
  if(ME_TIMER){clearTimeout(ME_TIMER);ME_TIMER=null;}
  function send(){ME_TIMER=null;return api('PUT','/api/v1/me/settings',meBody()).catch(function(){});}
  if(now){return send();}
  ME_TIMER=setTimeout(send,500);
  return Promise.resolve();
}
function flushMe(){return ME_TIMER?saveMe(true):Promise.resolve();}
function resetView(){
  ME_APPLYING=true;
  PAGESIZE=storedPageSize();SORT={col:'',dir:''};$('door-filter').value='';LOCFILTER='';PAGE=1;PAGEKEY='';
  ME_APPLYING=false;
  renderDoors();
}
$('btn-login').onclick=function(){
  setMsg('login-msg','');$('login-msg').textContent='';
  api('POST','/api/v1/login',{user:$('user').value,password:$('password').value}).then(function(r){
    $('password').value='';renderSession(r);
    return (CFG?Promise.resolve():loadAll()).then(function(){renderSession(r);if(DOORS.length){$('btn-load-doors').click();}return loadMe();});
  }).catch(function(e){$('login-msg').textContent=errText(e);});
};
$('password').onkeydown=function(ev){if(ev.key==='Enter'){$('btn-login').click();}};
$('btn-logout').onclick=function(){
  flushMe().then(function(){return api('POST','/api/v1/logout');}).then(function(s){clearAdminData();renderSession(s);stopPolling();LIVE=false;ACCT=false;if(s.behindProxy){clearView();}resetView();}).catch(function(e){$('login-msg').textContent=errText(e);});
};

/* ---- doors ---- */
function stateOn(){return !!(CFG&&CFG.doorState&&CFG.doorState.checks&&CFG.doorState.checks.length);}
function slim(d){return {id:d.id,name:d.name,extra:d.extra||{}};}
function aliasOf(d){var a=CFG&&CFG.aliases;return (a&&hasOwn(a,d.id))?String(a[d.id]):'';}
function doorTitle(d){var a=aliasOf(d);return d.name+(a?(' / '+a):'');}
/* the state shown for a door: the fresh one of this load, else the last known one (muted) */
function stOf(id){return STATES[id]||LAST[id]||null;}
function isFresh(id){var f=FRESH[id];return !!f&&(f===true||f>Date.now());}
function allFresh(ids){if(!stateOn()){return true;}for(var i=0;i<ids.length;i++){if(!isFresh(ids[i])){return false;}}return true;}
function freshCount(ids){var n=0;ids.forEach(function(id){if(isFresh(id)){n++;}});return n;}
/* why a door's action buttons are off ('' = ready): the rule is that no command goes out before the fresh state of this load is known */
function doorBlock(d){
  if(licBlocked()){return licTip();}
  if(!loggedIn()){return 'Log in with an AEOS user first.';}
  if(stateOn()&&!isFresh(d.id)){return (ACCT&&FRESH[d.id])?'The state of this door is older than '+FRESHSEC+' seconds. Waiting for the next live read.':'Waiting for the current state of this door.';}
  return '';
}
function batchBlock(ids){
  if(licBlocked()){return licTip();}
  if(!loggedIn()){return 'Log in with an AEOS user first.';}
  if(!allFresh(ids)){return 'Waiting for the current state: '+freshCount(ids)+' of '+ids.length+' door(s) read.';}
  return '';
}
function idsOf(doors){return doors.map(function(d){return d.id;});}
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
  ids.forEach(function(id){var st=stOf(id);if(st){n[st.state]=(n[st.state]||0)+1;}});
  var keys=Object.keys(n).sort(function(a,b){var x=order.indexOf(a),y=order.indexOf(b);x=x<0?99:x;y=y<0?99:y;return x!==y?x-y:(a<b?-1:1);});
  return keys.map(function(k){return n[k]+' '+k;}).join(', ');
}
/* sort: first click ascending, second descending, third back to the list order; text is case-insensitive and natural (D2 before D10);
   empty values go last. Sorting happens before paging. */
function sortVal(d,col){
  if(col==='alias'){return aliasOf(d);}
  if(col==='name'){return String(d.name||'');}
  if(col==='id'){return String(d.id);}
  if(col==='state'){var st=stOf(d.id);return st?String(st.state):'';}
  if(col.indexOf('x:')===0){return String((d.extra&&d.extra[col.slice(2)])||'');}
  if(col.indexOf('l:')===0){var pl=PLACE[d.id];return String((pl&&pl.fields[col.slice(2)])||'');}
  return '';
}
function sortDoors(list){
  if(!SORT.col||!SORT.dir){return list;}
  var dir=(SORT.dir==='desc')?-1:1;
  var keyed=list.map(function(d,i){return {d:d,i:i,v:sortVal(d,SORT.col)};});
  keyed.sort(function(a,b){
    if(a.v===''&&b.v!==''){return 1;}
    if(b.v===''&&a.v!==''){return -1;}
    var c=a.v.localeCompare(b.v,undefined,{numeric:true,sensitivity:'base'});
    return c?c*dir:a.i-b.i;
  });
  return keyed.map(function(k){return k.d;});
}
function clickSort(col){
  if(SORT.col!==col){SORT={col:col,dir:'asc'};}
  else if(SORT.dir==='asc'){SORT={col:col,dir:'desc'};}
  else{SORT={col:'',dir:''};}
  PAGE=1;renderDoors();saveMe();
}
function sortTh(text,col,attrs){
  var a=(SORT.col===col)?SORT.dir:'';
  var at={'class':'sortable','data-col':col,'data-sort':a,'aria-sort':(a==='asc'?'ascending':(a==='desc'?'descending':'none')),title:'Click to sort'};
  Object.keys(attrs||{}).forEach(function(k){at[k]=(k==='class')?('sortable '+attrs[k]):attrs[k];});
  var t=h('th',at);
  t.appendChild(document.createTextNode(text+(a==='asc'?' \u25B2':(a==='desc'?' \u25BC':''))));
  t.onclick=function(){clickSort(col);};
  return t;
}
function visibleDoors(){
  var f=$('door-filter').value.toLowerCase();
  var set=(LOCFILTER&&NODES[LOCFILTER])?NODES[LOCFILTER].set:null;
  return sortDoors(DOORS.filter(function(d){
    if(set&&!set[d.id]){return false;}
    if(!f){return true;}
    var pl=PLACE[d.id],loc='';
    if(pl){loc=Object.keys(pl.fields).map(function(k){return pl.fields[k]+' '+labelOf(pl.fields[k]);}).join(' ');}
    return (d.name+' '+d.id+' '+aliasOf(d)+' '+loc).toLowerCase().indexOf(f)>=0;
  }));
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
function hhmm(iso){var d=new Date(iso);if(isNaN(d.getTime())){return '';}function p(n){return (n<10?'0':'')+n;}return p(d.getHours())+':'+p(d.getMinutes());}
/* last=true: the state is the remembered one from an earlier read, painted muted until the fresh read of this load arrives */
function paintState(td,st,last){
  var k=stateKind(st.state);
  td.title=last?('last known '+hhmm(st.at)+(st.detail?(' - '+st.detail):'')):(st.detail||'');
  td.className='state'+(st.state==='?'?' unknown':'')+(last?' last':'');
  if(last){td.setAttribute('data-last','1');}else{td.removeAttribute('data-last');}
  td.innerHTML='';
  var c=h('span',{class:'schip s-'+k+(last?' last':'')});c.innerHTML=STATE_ICONS[k];c.appendChild(document.createTextNode(st.state));
  td.appendChild(c);
}
function paintStateCell(id){
  var row=rowOf(id);if(!row){return;}
  var td=row.querySelector('td.state');if(!td){return;}
  if(STATES[id]){paintState(td,STATES[id],false);}else if(LAST[id]){paintState(td,LAST[id],true);}
}
function paintRowButtons(id){
  var row=rowOf(id);if(!row){return;}
  var d=null;for(var i=0;i<DOORS.length;i++){if(DOORS[i].id===id){d=DOORS[i];break;}}
  if(!d){return;}
  var why=doorBlock(d);
  Array.prototype.forEach.call(row.querySelectorAll('button.act'),function(b){if(!b.getAttribute('data-busy')){b.disabled=!!why;b.title=why;}});
}
/* a read state ("?" = the read failed) is fresh only when it is a real answer */
function applyStates(list){
  list.forEach(function(x){
    STATES[x.id]={state:x.state,detail:x.detail};
    if(ACCT){TIMED=true;}
    FRESH[x.id]=(x.state==='?')?false:(ACCT?(Date.now()+Math.max(0,FRESHSEC-(x.ageSec||0))*1000):true);
    paintStateCell(x.id);paintRowButtons(x.id);
  });
  updateBatchBar();
}
function setState(id,state,detail){applyStates([{id:id,state:state,detail:detail}]);}
function renderCounts(){
  paintTree();
  var box=$('door-counts');box.innerHTML='';
  if(!DOORS.length){return;}
  box.appendChild(h('span',{text:DOORS.length+' doors'}));
  if(!stateOn()){return;}
  var n={locked:0,unlocked:0,normal:0,unknown:0};
  DOORS.forEach(function(d){var st=stOf(d.id);n[st?stateKind(st.state):'unknown']+=1;});
  ['locked','unlocked','normal','unknown'].forEach(function(k){box.appendChild(h('span',{class:'s-'+k,text:n[k]+' '+k}));});
}
function updateBatchBar(){
  var sel=selectedDoors().length;
  $('batch-bar').style.display=DOORS.length?'':'none';
  $('batch-count').textContent=sel+' selected';
  var selWhy=batchBlock(Object.keys(SEL).filter(function(k){return SEL[k];}));
  Array.prototype.forEach.call($('batch-buttons').children,function(b){b.disabled=(sel===0)||BATCH_BUSY||!!selWhy;b.title=selWhy;});
  $('btn-lockdown').style.display=isMapped(CFG&&CFG.actions.lock)?'':'none';
  var allWhy=batchBlock(idsOf(DOORS));
  $('btn-lockdown').disabled=BATCH_BUSY||!DOORS.length||!!allWhy;$('btn-lockdown').title=allWhy;
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
      sel.onchange=function(){PAGESIZE=parseInt(sel.value,10)||0;if(loggedIn()){saveMe();}else{try{localStorage.setItem('dk-rows-per-page',String(PAGESIZE));}catch(e){}}PAGE=1;renderDoors();};
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
    else{
      var ids=own?Object.keys(SEL).filter(function(k){return SEL[k];}):(b._ids?b._ids():null);
      if(ids){why=batchBlock(ids);}
    }
    b.disabled=!!why||BATCH_BUSY||(own&&sel===0)||b.getAttribute('data-n')==='0';
    b.title=why;
  });
  var rb=$('arm-retry');
  if(rb){rb.disabled=BATCH_BUSY||licBlocked()||!loggedIn()||!ARMREP||!ARMREP.failed.length||!allFresh(ARMREP.failed);}
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
  nm.onclick=function(){LOCFILTER=(LOCFILTER===n.key)?'':n.key;renderDoors();saveMe();};
  var scope={name:(n.key==='(unplaced)')?'the doors without a location':pathName(n.path),label:'location: '+n.key};
  ar.onclick=function(){armRun('arm',nodeDoors(n),scope);};
  di.onclick=function(){armRun('disarm',nodeDoors(n),scope);};
  ar._ids=di._ids=function(){return n.ids;};
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
    ar._ids=di._ids=function(){return idsOf(ds);};
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
    var xa=aliasOf({id:x.id});
    body.appendChild(h('tr',{'data-id':x.id},[h('td',{text:x.name+(xa?(' / '+xa):'')+' ('+x.id+')'}),h('td',{text:pl?pl.text:''}),
      h('td',{text:(x.fault||'no reply')+(x.refused?' (refused, not sent)':'')}),h('td',{text:stt?stt.state:''})]));
  });
  $('arm-report-table').style.display=fails.length?'':'none';
  $('arm-export').disabled=!ARMREP.file;
  paintArm(selectedDoors().length);
}
function renderDoors(){
  if(!CFG){$('doors-head').innerHTML='';$('doors-body').innerHTML='';$('batch-bar').style.display='none';$('door-counts').innerHTML='';$('pager-top').style.display='none';$('pager-bottom').style.display='none';return;}
  var extras=(CFG&&CFG.actions.listDoors.extraFields)||[];
  var levels=locLevels();
  placeAll();
  if(TREE_DOORS!==DOORS||TREE_LOC!==JSON.stringify((CFG&&CFG.locations)||null)){renderTree();}
  if(DOORS.length&&LOCFILTER&&!NODES[LOCFILTER]){LOCFILTER='';}
  renderGroups();
  $('loc-side').style.display=(DOORS.length&&(levels.length||((CFG&&CFG.groups)||[]).length))?'':'none';
  $('loc-tree-box').style.display=levels.length?'':'none';
  var head=$('doors-head');head.innerHTML='';
  var selAll=h('input',{type:'checkbox',id:'sel-all',title:'Select all doors on this page'});
  var tr=h('tr',null,[h('th',null,[selAll]),sortTh('Alias','alias'),sortTh('Name','name'),sortTh('Id','id')]);
  extras.forEach(function(x){tr.appendChild(sortTh(x,'x:'+x));});
  levels.forEach(function(x){tr.appendChild(sortTh(x,'l:'+x,{'class':'loc-th','data-level':x}));});
  if(stateOn()){tr.appendChild(sortTh('State','state'));}
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
  var key=$('door-filter').value+'|'+LOCFILTER+'|'+SORT.col+'|'+SORT.dir;
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
    var acell=h('td',{'class':'alias'+(isAdmin()?' editable':''),text:aliasOf(d)});
    if(isAdmin()){acell.title='Click to edit the alias';acell.onclick=function(){editAlias(acell,d);};}
    var row=h('tr',{'data-id':d.id},[h('td',null,[cb]),acell,h('td',{'class':'dname',text:d.name}),h('td',{text:d.id})]);
    extras.forEach(function(x){row.appendChild(h('td',{text:(d.extra&&d.extra[x])||''}));});
    var pl=PLACE[d.id];
    row.setAttribute('data-loc',pl?pl.text:'');
    levels.forEach(function(x){var v=(pl&&pl.fields[x])||'';row.appendChild(h('td',{'class':'loc-td','data-level':x,text:v,title:(v&&labelOf(v)!==v)?labelOf(v):''}));});
    if(stateOn()){
      var stc=h('td',{class:'state'});
      if(STATES[d.id]){paintState(stc,STATES[d.id],false);}else if(LAST[d.id]){paintState(stc,LAST[d.id],true);}
      row.appendChild(stc);
    }
    var acts=h('td');var res=h('td',{class:'result'});
    if(RES[d.id]){paintResult(res,RES[d.id]);}
    DOOR_ACTIONS.forEach(function(a){
      var def=CFG.actions[a];if(!isMapped(def)){return;}
      var btn=h('button',{class:'act','data-action':a,text:def.label||a});
      btn.onclick=function(){runAction(a,d,btn);};
      var why=doorBlock(d);btn.disabled=!!why;btn.title=why;
      acts.appendChild(btn);
    });
    row.appendChild(acts);row.appendChild(res);body.appendChild(row);
  });
  updateBatchBar();
}
function runAction(a,d,btn){
  var def=CFG.actions[a];
  var al=aliasOf(d);
  var p=(def.confirm===false)?Promise.resolve(true):confirmDialog((def.label||a)+' door "'+d.name+'"'+(al?(' (alias "'+al+'")'):'')+' ('+d.id+')?');
  p.then(function(ok){
    if(!ok){return;}
    btn.disabled=true;btn.setAttribute('data-busy','1');setRowResult(d.id,'','working...');
    return api('POST','/api/v1/doors/action',{action:a,id:d.id,name:d.name,extra:d.extra||{}}).then(function(r){
      setRowResult(d.id,r.ok?'ok':'bad',r.ok?(r.transport==='socket'?('OK (socket) reply: '+(r.reply||'')+' request id '+r._rid):('OK (HTTP '+r.httpStatus+') request id '+r._rid)):('FAILED: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')'),r._rid);
      if(r.state!==undefined&&r.state!==null){setState(d.id,r.state,r.stateDetail);}
      else if(stateOn()){return readSome([d]);}
    }).catch(function(e){
      setRowResult(d.id,'bad','FAILED: '+errText(e),e.rid||'-');
    }).then(function(){btn.removeAttribute('data-busy');paintRowButtons(d.id);});
  });
}
/* State of the listed doors: one request, one socket session on the server. */
/* Progressive read: chunks of STATE_CHUNK doors, one request (one socket session) each; every chunk paints as it arrives and
   enables the buttons of its doors. A newer read (new Load doors, Refresh state) makes an older one stop. */
function refreshStates(doors){
  if(!stateOn()||!doors.length){return Promise.resolve();}
  var gen=++READGEN,total=doors.length,done=0,failed=null,rid='',seen={};
  var CH=Math.max(1,Math.min(STATE_CHUNK,(CFG&&CFG.doorState&&parseInt(CFG.doorState.maxDoorsPerRefresh,10))||STATE_CHUNK));var chunks=[];for(var i=0;i<doors.length;i+=CH){chunks.push(doors.slice(i,i+CH));}
  $('btn-refresh-state').disabled=true;
  setMsg('doors-msg','State '+done+' of '+total+' read');
  var p=Promise.resolve();
  chunks.forEach(function(ch){
    p=p.then(function(){
      if(gen!==READGEN||failed){return;}
      return api('POST','/api/v1/doors/state',{doors:ch.map(slim)}).then(function(r){
        if(gen!==READGEN){return;}
        (r.states||[]).forEach(function(x){seen[x.id]=true;});
        applyStates(r.states||[]);done+=ch.length;rid=r._rid;
        if(done<total){setMsg('doors-msg','State '+done+' of '+total+' read');}
      }).catch(function(e){if(gen===READGEN){failed=e;}});
    });
  });
  return p.then(function(){
    if(gen!==READGEN){return;}
    $('btn-refresh-state').disabled=false;
    if(failed){
      applyStates(doors.filter(function(d){return !seen[d.id];}).map(function(d){return {id:d.id,state:'?',detail:failed.message};}));
      setMsg('doors-msg','State not read: '+errText(failed),'bad');
    }
    else{setMsg('doors-msg','State of '+total+' door(s) read (request id '+rid+')','good');}
  });
}
/* a few doors (after a door action): does not stop a bigger read that is running */
function readSome(doors){
  return api('POST','/api/v1/doors/state',{doors:doors.map(slim)}).then(function(r){applyStates(r.states||[]);}).catch(function(e){
    applyStates(doors.map(function(d){return {id:d.id,state:'?',detail:e.message};}));setMsg('doors-msg','State not read: '+errText(e),'bad');
  });
}
/* the doors on the shown page first, then the rest of the filtered list, then all the others */
function readOrder(all){
  var seen={},out=[];
  function add(list){list.forEach(function(d){if(!seen[d.id]){seen[d.id]=true;out.push(d);}});}
  add(PAGEROWS);add(visibleDoors());if(all){add(DOORS);}
  return out;
}
/* A batch runs as a background job on the server (one per operator); the page follows its progress and takes the report at the end. */
function followJob(id,total){
  return new Promise(function(resolve,reject){
    var box=$('job-bar');box.style.display='';
    var n=0;
    function paint(j){
      $('job-text').textContent='Job '+id+': '+(j.phase||j.state)+' - '+j.done+' of '+j.total+' door(s)';
      var p=$('job-progress');p.max=Math.max(1,j.total);p.value=j.done;
    }
    paint({phase:'Started',done:0,total:total,state:'queued'});
    function tick(){
      api('GET','/api/v1/jobs/'+id).then(function(j){
        paint(j);
        if(j.state==='done'){var res=j.result||{};res._rid=id;resolve(res);}
        else if(j.state==='failed'){var e=new Error((j.error&&j.error.message)||'The job failed.');e.rid=id;e.code=(j.error&&j.error.code)||'';reject(e);}
        else{n++;setTimeout(tick,n<10?400:1000);}
      }).catch(reject);
    }
    tick();
  });
}
/* One action on many doors: the server runs it as a job with the operator's own AEOS account. */
function runBatch(a,doors,question,opts,meta){
  if(!doors.length||BATCH_BUSY){return;}
  var names=doors.slice(0,5).map(doorTitle).join(', ')+(doors.length>5?', ...':'');
  confirmDialog(question+' First '+Math.min(5,doors.length)+': '+names,opts).then(function(ok){
    if(!ok){return;}
    BATCH_BUSY=true;updateBatchBar();
    doors.forEach(function(d){setRowResult(d.id,'','working on '+doors.length+' doors...');});
    setMsg('doors-msg','Working on '+doors.length+' door(s)...');
    var req={action:a,doors:doors.map(slim)};
    if(meta&&meta.report){req.report=meta.report;}
    return api('POST','/api/v1/doors/batch',req).then(function(j){return followJob(j.jobId,doors.length);}).then(function(r){
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
/* ---- live states: GET /api/v1/doors/states?since=<version> every 3 s while the server account reads the door states ---- */
function stopPolling(){if(POLL_TIMER){clearTimeout(POLL_TIMER);POLL_TIMER=null;}POLL_BUSY=false;POLL_GEN++;}function tickFresh(){if(!TIMED||!loggedIn()||!DOORS.length){return;}PAGEROWS.forEach(function(d){paintRowButtons(d.id);});updateBatchBar();}
function startFreshTick(){if(!FRESH_TIMER){FRESH_TIMER=setInterval(tickFresh,2000);}}
function startPolling(){stopPolling();VER=0;POLL_DELAY=3000;return pollStates(POLL_GEN);}
function schedulePoll(g){if(g!==POLL_GEN){return;}POLL_TIMER=setTimeout(function(){pollStates(g);},POLL_DELAY);}
/* a failing poll does not end live mode: it keeps trying with a longer pause (up to 30 s), says "paused", and resumes by itself */
function pollPaused(why){
  var was=LIVE;LIVE=false;POLL_DELAY=Math.min(30000,POLL_DELAY*2);
  setMsg('doors-msg','Live states paused: '+why+' The page keeps trying; states older than '+FRESHSEC+' seconds switch the buttons off. Refresh state reads them with your own account.','bad');
  if(was||true){PAGEROWS.forEach(function(d){paintRowButtons(d.id);});updateBatchBar();}
}
function pollStates(g){
  if(g===undefined){g=POLL_GEN;}
  if(!loggedIn()||!DOORS.length||POLL_BUSY){return Promise.resolve();}
  POLL_BUSY=true;
  return api('GET','/api/v1/doors/states?since='+VER).then(function(r){
    POLL_BUSY=false;
    if(g!==POLL_GEN){return;}
    FRESHSEC=r.freshSeconds||FRESHSEC;
    if(!r.account){
      ACCT=false;LIVE=false;stopPolling();
      setMsg('doors-msg','Live door states are not available now. Use Refresh state to read them.','bad');
      DOORS.forEach(function(d){paintRowButtons(d.id);});updateBatchBar();
      return;
    }
    ACCT=true;
    if(!r.live){pollPaused('the server could not read the door states just now.');schedulePoll(g);return;}
    if(!LIVE){setMsg('doors-msg','Live door states are back.','good');}
    LIVE=true;VER=r.ver;POLL_DELAY=3000;
    var known={};DOORS.forEach(function(d){known[d.id]=true;});
    var list=[];
    Object.keys(r.states||{}).forEach(function(id){if(known[id]){var x=r.states[id];list.push({id:id,state:x.state,detail:x.detail,ageSec:x.ageSec});}});
    if(list.length){applyStates(list);}
    else{PAGEROWS.forEach(function(d){paintRowButtons(d.id);});updateBatchBar();}
    schedulePoll(g);
  }).catch(function(e){
    POLL_BUSY=false;
    if(g!==POLL_GEN||(e&&e.cancelled)){return;}
    if(e&&e.code==='session_expired'){return;}
    pollPaused('the console cannot be reached.');schedulePoll(g);
  });
}$('btn-refresh-state').onclick=function(){if(LIVE){VER=0;pollStates(POLL_GEN);}else{refreshStates(readOrder(false));}};
$('btn-arm').onclick=function(){var ds=selectedDoors();armRun('arm',ds,selScope(ds));};
$('btn-disarm').onclick=function(){var ds=selectedDoors();armRun('disarm',ds,selScope(ds));};
$('loc-filter-clear').onclick=function(){LOCFILTER='';renderDoors();saveMe();};
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
    READGEN++;stopPolling();
    DOORS=r.doors||[];SEL={};STATES={};FRESH={};LAST=r.lastKnown||{};RES={};PAGE=1;ARMREP=null;$('arm-report').style.display='none';$('job-bar').style.display='none';
    ACCT=!!r.account&&stateOn();TIMED=false;LIVE=ACCT&&!!r.live;FRESHSEC=r.freshSeconds||FRESHSEC;startFreshTick();
    renderDoors();updateLocTest();loadLicense();
    if(r.ok){
      setMsg('doors-msg',DOORS.length+' door(s) loaded (request id '+r._rid+')'+(LIVE?'. The server reads the door states live.':''),'good');
      if(ACCT&&DOORS.length){startPolling();}
      if(stateOn()&&DOORS.length&&!LIVE){return refreshStates(readOrder(true));}
    }
    else{setMsg('doors-msg','AEOS answered with an error: '+(r.fault||('HTTP '+r.httpStatus))+' (request id '+r._rid+')','bad');}
  }).catch(function(e){DOORS=[];renderDoors();setMsg('doors-msg',errText(e),'bad');});
};
$('door-filter').oninput=function(){renderDoors();saveMe();};

/* ---- alias: edit in the table cell (admin), CSV import / export (Setup tab) ---- */
function editAlias(td,d){
  if(td.querySelector('input')){return;}
  var cur=aliasOf(d),finished=false;
  var inp=h('input',{type:'text','class':'alias-edit',maxlength:'200','data-id':d.id,'aria-label':'Alias of '+d.name});
  inp.value=cur;td.textContent='';td.appendChild(inp);inp.focus();inp.select();
  function cancel(){if(finished){return;}finished=true;td.textContent=cur;}
  function save(){
    if(finished){return;}
    finished=true;
    var v=inp.value.trim();
    if(v===cur){td.textContent=cur;return;}
    td.textContent='saving...';
    api('PUT','/api/v1/aliases/'+encodeURIComponent(d.id),{alias:v}).then(function(r){
      if(!CFG.aliases){CFG.aliases={};}
      if(r.alias){CFG.aliases[d.id]=r.alias;}else{delete CFG.aliases[d.id];}
      td.textContent=r.alias||'';
      setMsg('doors-msg',r.alias?('Alias of '+d.name+' saved (request id '+r._rid+')'):('Alias of '+d.name+' removed (request id '+r._rid+')'),'good');
    }).catch(function(e){td.textContent=cur;setMsg('doors-msg','Alias not saved: '+errText(e),'bad');});
  }
  inp.onkeydown=function(ev){
    if(ev.key==='Escape'){ev.preventDefault();cancel();}
    else if(ev.key==='Enter'){ev.preventDefault();save();}
  };
  inp.onblur=cancel;
}
function csvCell(v){
  var t=String(v==null?'':v);
  if(/^\s*[=+\-@\t\r]/.test(t)){t="'"+t;}
  if(/[";\r\n]/.test(t)){t='"'+t.replace(/"/g,'""')+'"';}
  return t;
}
function csvUnprotect(v){return /^'[=+\-@\t\r]/.test(v)?v.slice(1):v;}
/* semicolon-separated, double quotes for cells with ; " or line breaks */
function parseCsv(text){
  text=text.replace(/^\uFEFF/,'');
  var rows=[],row=[],cell='',q=false,i,c;
  for(i=0;i<text.length;i++){
    c=text.charAt(i);
    if(q){
      if(c==='"'){if(text.charAt(i+1)==='"'){cell+='"';i++;}else{q=false;}}
      else{cell+=c;}
    }
    else if(c==='"'&&cell===''){q=true;}
    else if(c===';'){row.push(cell);cell='';}
    else if(c==='\n'||c==='\r'){
      if(c==='\r'&&text.charAt(i+1)==='\n'){i++;}
      row.push(cell);cell='';rows.push(row);row=[];
    }
    else{cell+=c;}
  }
  if(cell!==''||row.length){row.push(cell);rows.push(row);}
  return rows.filter(function(r){return !(r.length===1&&r[0].trim()==='');});
}
$('btn-alias-export').onclick=function(){
  if(!DOORS.length){setMsg('alias-msg','Load the doors first (Doors tab), then export.','bad');return;}
  var lines=['id;name;alias'].concat(DOORS.map(function(d){return [d.id,d.name,aliasOf(d)].map(csvCell).join(';');}));
  var u=URL.createObjectURL(new Blob([lines.join('\r\n')+'\r\n'],{type:'text/csv'}));
  var a=h('a',{href:u,download:'doorkeeper-aliases.csv'});document.body.appendChild(a);a.click();a.remove();
  setTimeout(function(){URL.revokeObjectURL(u);},5000);
  setMsg('alias-msg',DOORS.length+' door(s) exported.','good');
};
$('btn-alias-import').onclick=function(){
  var f=$('alias-file').files&&$('alias-file').files[0];
  if(!f){setMsg('alias-msg','Choose the CSV file first.','bad');return;}
  f.text().then(function(text){
    var rows=parseCsv(text);
    if(rows.length&&rows[0][0].trim().toLowerCase()==='id'){rows.shift();}
    var ids={},byName={};
    DOORS.forEach(function(d){ids[d.id]=d;(byName[d.name]=byName[d.name]||[]).push(d.id);});
    var upd={},n=0,unknown=[],tooLong=0,bad=0;
    rows.forEach(function(r){
      if(r.length<2){bad++;return;}
      var key=csvUnprotect(r[0].trim()),al=csvUnprotect((r.length>=3?r[2]:r[1]).trim()),id=null;
      if(!DOORS.length||ids[key]){id=key;}
      else if(byName[key]&&byName[key].length===1){id=byName[key][0];}
      if(id===null){unknown.push(key);return;}
      if(al.length>200){tooLong++;return;}
      upd[id]=al;n++;
    });
    if(!n){setMsg('alias-msg','Nothing imported: '+unknown.length+' unknown door(s), '+bad+' bad line(s), '+tooLong+' too long.','bad');return;}
    return api('PUT','/api/v1/aliases',{aliases:upd}).then(function(r){
      if(!CFG.aliases){CFG.aliases={};}
      Object.keys(upd).forEach(function(k){if(upd[k]){CFG.aliases[k]=upd[k];}else{delete CFG.aliases[k];}});
      renderDoors();
      setMsg('alias-msg','Imported '+n+' alias(es)'+(unknown.length?(', '+unknown.length+' unknown door(s) skipped (first: '+unknown.slice(0,3).join(', ')+')'):'')+(tooLong?(', '+tooLong+' too long skipped'):'')+(bad?(', '+bad+' bad line(s) skipped'):'')+' (request id '+r._rid+').','good');
    });
  }).catch(function(e){setMsg('alias-msg','Import failed: '+errText(e),'bad');});
};

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
  $('sk-loginTemplate').value=k.loginTemplate;$('sk-loginSuccessPattern').value=k.loginSuccessPattern;paintPatternWarn();$('sk-initCommands').value=(k.initCommands||[]).join('\n');
  var ds=CFG.doorState||{};var dc=ds.checks||[];
  for(var i=1;i<=DS_ROWS;i++){var c=dc[i-1]||{};$('ds-label-'+i).value=c.label||'';$('ds-cmd-'+i).value=c.command||'';$('ds-match-'+i).value=c.matchPattern||'';}
  $('ds-otherwise').value=ds.otherwiseLabel||'';$('ds-max').value=ds.maxDoorsPerRefresh||500;
  var l=CFG.actions.listDoors;$('itemElement').value=l.itemElement;$('idField').value=l.idField;$('nameField').value=l.nameField;
  $('extraFields').value=(l.extraFields||[]).join(', ');$('pageSize').value=l.pageSize||0;
  fillLocations();
  $('cfg-admins').value=((CFG.access&&CFG.access.admins)||[]).join('\n');
  $('cfg-idleMinutes').value=(CFG.access&&CFG.access.idleMinutes)||15;
  $('cfg-pollSeconds').value=(CFG.doorState&&CFG.doorState.pollSeconds)||30;
  $('cfg-freshSeconds').value=(CFG.doorState&&CFG.doorState.freshSeconds)||120;
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
  c.doorState={checks:dchecks,otherwiseLabel:$('ds-otherwise').value.trim(),maxDoorsPerRefresh:parseInt($('ds-max').value,10)||500,
    pollSeconds:parseInt($('cfg-pollSeconds').value,10)||30,freshSeconds:parseInt($('cfg-freshSeconds').value,10)||120};
  var l=c.actions.listDoors;l.itemElement=$('itemElement').value.trim();l.idField=$('idField').value.trim();l.nameField=$('nameField').value.trim();
  l.extraFields=$('extraFields').value.split(',').map(function(s){return s.trim();}).filter(function(s){return s;});
  l.pageSize=parseInt($('pageSize').value,10)||0;
  c.locations=readLocations();
  c.groups=readGroups();
  c.arming={armAction:$('arm-action').value,disarmAction:$('disarm-action').value,armLabel:$('arm-label').value.trim(),disarmLabel:$('disarm-label').value.trim()};
  c.access={admins:$('cfg-admins').value.split('\n').map(function(x){return x.trim();}).filter(function(x){return x;}),idleMinutes:parseInt($('cfg-idleMinutes').value,10)||15};
  return c;
}
/* Save what is on the Setup tab, then reload it from the server (header, banners, doors follow). */
function saveSetup(){
  return api('PUT','/api/v1/config',readSetup()).then(function(r){
    return api('GET','/api/v1/config').then(function(c){CFG=c;fillSetup();renderBanners();renderDoors();return loadLicense().then(function(){return api('GET','/api/v1/session');}).then(function(s){renderSession(s);loadServerAccount();return r;});});
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
function auditQuery(){
  var p=[];
  [['user','aud-user'],['door','aud-door'],['action','aud-action'],['from','aud-from'],['to','aud-to']].forEach(function(x){
    var v=$(x[1]).value.trim();if(v&&v!=='all'){p.push(x[0]+'='+encodeURIComponent(v));}
  });
  return p;
}
function loadAudit(){
  api('GET','/api/v1/audit?'+['limit=200'].concat(auditQuery()).join('&')).then(function(r){
    var b=$('audit-body');b.innerHTML='';
    (r.records||[]).slice().reverse().forEach(function(x){
      b.appendChild(h('tr',null,[h('td',{text:x.ts}),h('td',{text:x.computer||''}),h('td',{text:x.windowsUser}),h('td',{text:x.aeosUser}),h('td',{text:x.action+(x.batch?(' ['+x.batch+']'):'')}),
        h('td',{text:x.doorId?((x.doorName||'')+' ('+x.doorId+')'):(x.doorName||'')}),h('td',{text:x.doorAlias||''}),h('td',{text:String(x.httpStatus)}),h('td',{text:x.ok?'yes':'NO'}),h('td',{text:x.fault||''})]));
    });
    var c=$('audit-chain');c.textContent=r.chainOk?('Chain OK ('+r.total+' records)'):('CHAIN BROKEN at record '+(r.badIndex+1));
    c.className=r.chainOk?'msg good':'msg bad';setMsg('audit-msg','');
    $('audit-count').textContent=(r.matched!==r.total)?(r.matched+' of '+r.total+' records match the filter'+(r.matched>(r.records||[]).length?(', the last '+(r.records||[]).length+' are shown'):'')):'';
  }).catch(function(e){setMsg('audit-msg',errText(e),'bad');});
}
$('btn-audit-refresh').onclick=loadAudit;
$('btn-audit-export').onclick=function(){
  download('/api/v1/audit/export'+(auditQuery().length?('?'+auditQuery().join('&')):''),'doorkeeper-audit.csv').catch(function(e){setMsg('audit-msg','Export failed: '+e.message,'bad');});
};

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

function paintPatternWarn(){$('sk-pattern-warn').style.display=$('sk-loginSuccessPattern').value.trim()?'none':'';}
$('sk-loginSuccessPattern').oninput=paintPatternWarn;
/* ---- server account (admin): set / replace / remove; the password is never read back ---- */
function fmtTime(iso){if(!iso){return '';}var d=new Date(iso);return isNaN(d.getTime())?iso:d.toLocaleString();}
function paintServerAccount(a){
  var st=$('sa-status');
  var txt=a.message||'';
  if(a.set){txt='Set by '+a.setBy+' at '+fmtTime(a.setAt)+(a.lastLoginOkAt?(', last login OK at '+fmtTime(a.lastLoginOkAt)):', no successful login yet')+'. '+(a.state==='reenter'?'Server account must be entered again.':(a.state==='login-failed'?('The last read failed: '+(a.lastError||'')):''));}
  st.textContent=txt;st.setAttribute('data-state',a.state||'none');
  $('btn-sa-save').textContent=a.set?'Replace server account':'Set server account';
  $('btn-sa-remove').disabled=!a.set;
}
function loadServerAccount(){
  if(!isAdmin()){return Promise.resolve();}
  return api('GET','/api/v1/server-account').then(paintServerAccount).catch(function(e){setMsg('sa-msg','Server account status not read: '+errText(e),'bad');});
}
$('btn-sa-save').onclick=function(){
  var u=$('sa-user').value.trim(),p=$('sa-password').value;
  if(!u||!p){setMsg('sa-msg','Enter the user name and the password.','bad');return;}
  setMsg('sa-msg','Checking the account with AEOS...');
  api('PUT','/api/v1/server-account',{user:u,password:p}).then(function(a){
    $('sa-password').value='';$('sa-user').value='';paintServerAccount(a);setMsg('sa-msg','Server account saved. The password is stored encrypted and is not shown again.','good');
  }).catch(function(e){$('sa-password').value='';setMsg('sa-msg','Not saved: '+errText(e),'bad');});
};
$('btn-sa-remove').onclick=function(){
  confirmDialog('Remove the server account? Door states are then read only when an operator loads the doors.',{title:'Remove server account',ok:'Remove',danger:true}).then(function(ok){
    if(!ok){return;}
    api('DELETE','/api/v1/server-account').then(function(a){paintServerAccount(a);setMsg('sa-msg','Server account removed.','good');}).catch(function(e){setMsg('sa-msg','Not removed: '+errText(e),'bad');});
  });
};

/* ---- start ---- */
buildSetupActions();
buildDoorStateSetup();
buildLocationSetup();
api('GET','/api/v1/session').then(function(s){
  renderSession(s);
  if(s.loggedIn||!s.behindProxy){return loadAll().then(function(){renderSession(s);return loadMe();});}
}).catch(function(e){
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

function Start-PortRelay {
    # IIS HttpPlatformHandler hands the child a port (%HTTP_PLATFORM_PORT%) and only accepts a child that listens on it with a plain
    # TCP socket (a child that listens through HTTP.sys is answered 502.3 and restarted). This binds that port on 127.0.0.1 and
    # copies every connection to DoorKeeper's own listener on -TargetPort, byte for byte, in both directions (nothing is parsed).
    # At most -Max connections at a time; one side ending closes the other. Returns the relay object; throws when the port is taken.
    param([int]$ListenPort, [int]$TargetPort, [int]$Max = 200)
    if (-not ('DkRelay' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
public class DkRelay {
    TcpListener listener; int target; int max; int active; volatile bool stopped;
    public int Active { get { return active; } }
    public DkRelay(int listenPort, int targetPort, int maxConnections) {
        listener = new TcpListener(IPAddress.Loopback, listenPort); target = targetPort; max = maxConnections;
    }
    public void Start() {
        listener.Start();
        Thread t = new Thread(AcceptLoop); t.IsBackground = true; t.Start();
    }
    public void Stop() { stopped = true; try { listener.Stop(); } catch { } }
    void AcceptLoop() {
        while (!stopped) {
            TcpClient c;
            try { c = listener.AcceptTcpClient(); } catch { if (stopped) return; Thread.Sleep(50); continue; }
            if (Interlocked.Increment(ref active) > max) { Interlocked.Decrement(ref active); try { c.Close(); } catch { } continue; }
            TcpClient cc = c;
            Thread h = new Thread(delegate() { Handle(cc); }); h.IsBackground = true; h.Start();
        }
    }
    void Handle(TcpClient c) {
        TcpClient u = null;
        try {
            u = new TcpClient(); u.NoDelay = true; c.NoDelay = true;
            u.Connect(IPAddress.Loopback, target);
            System.IO.Stream a = c.GetStream(); System.IO.Stream b = u.GetStream();
            TcpClient cl = c, up = u;
            Thread back = new Thread(delegate() { Pump(b, a, cl, up); }); back.IsBackground = true; back.Start();
            Pump(a, b, c, u);
            back.Join(5000);
        } catch { }
        finally {
            try { c.Close(); } catch { }
            try { if (u != null) u.Close(); } catch { }
            Interlocked.Decrement(ref active);
        }
    }
    static void Pump(System.IO.Stream from, System.IO.Stream to, TcpClient c, TcpClient u) {
        byte[] buf = new byte[16384];
        try { int n; while ((n = from.Read(buf, 0, buf.Length)) > 0) { to.Write(buf, 0, n); to.Flush(); } } catch { }
        finally { try { c.Close(); } catch { } try { u.Close(); } catch { } }
    }
}
'@
    }
    $relay = New-Object DkRelay($ListenPort, $TargetPort, $Max)
    $relay.Start()
    return $relay
}

function Start-Console {
    if (-not $ConfigFile) {
        $script:ConfigPath = Join-Path $script:ScriptDir 'doorkeeper.json'
        $oldCfg = Join-Path $script:ScriptDir 'aeos-console.json'
        if (-not (Test-Path -LiteralPath $script:ConfigPath) -and (Test-Path -LiteralPath $oldCfg)) { $script:ConfigPath = $oldCfg }
    }
    else { $script:ConfigPath = [System.IO.Path]::GetFullPath($ConfigFile) }
    # Behind the proxy DoorKeeper's own listener is on -InternalPort and -Port belongs to the relay.
    $relayPort = $Port
    $listenPort = $Port
    if ($BehindProxy) { $listenPort = $InternalPort }
    $script:Port = $listenPort
    $script:Cred = $null
    $script:Sess = $null
    $script:Sessions = @{}
    $script:Jobs = [hashtable]::Synchronized(@{})
    $script:LoginAttempts = @{}
    $script:LogLock = New-Object System.Object
    $script:RequestClient = $null
    $script:PublicOrigin = ''
    if ($script:BehindProxy) {
        $script:PublicOrigin = Get-PublicOrigin -Url $PublicUrl
        if (-not $script:PublicOrigin) {
            Write-Host '-BehindProxy needs -PublicUrl with the address operators use, for example https://doorkeeper.example.org (http:// is accepted for localhost only).'
            exit 1
        }
    }
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
    $script:DebugLogPath = Resolve-DataPath -Value ([string]$script:Config.debugLogFile) -BaseDir $script:ScriptDir -DefaultName 'doorkeeper-debug.log'
    # One instance per data folder: two processes would break the audit hash chain and double the state polling.
    # Behind IIS a recycle starts the new process before the old one has gone, so it waits a few seconds for the lock.
    $lockWait = 0
    if ($script:BehindProxy) { $lockWait = 8 }
    $script:InstanceLock = Open-InstanceLock -Path (Join-Path $script:DataDir 'doorkeeper.lock') -WaitSeconds $lockWait
    if ($null -eq $script:InstanceLock) {
        $msg = 'Another DoorKeeper instance already uses the data folder ' + $script:DataDir + ' (lock file doorkeeper.lock). This instance stops.'
        Write-DebugLog 'startup' $msg 'ERROR'
        Write-Host $msg
        exit 1
    }
    # Only the instance that holds the lock reads the head of the audit chain.
    Initialize-Paths
    $script:UsersPath = Join-Path $script:DataDir 'doorkeeper-users.json'
    $script:StateCachePath = Join-Path $script:DataDir 'doorkeeper-state-cache.json'
    $script:ServerAccountPath = Join-Path $script:DataDir 'doorkeeper-server-account.bin'
    $script:ServerAccountMetaPath = Join-Path $script:DataDir 'doorkeeper-server-account.json'
    Read-UserSettingsFile
    Read-StateCacheFile
    $url = 'http://localhost:' + $listenPort + '/'
    Write-StartupBlock -Url $url
    if ($script:BehindProxy) { Write-DebugLog 'startup' ('Behind a proxy: public origin ' + $script:PublicOrigin + '; the client address is read from X-DK-Client-IP on requests from 127.0.0.1 only; relay on 127.0.0.1:' + $relayPort + ' -> ' + $InternalPort + '.') }
    foreach ($p in $problems) { Write-DebugLog 'startup' ('Config problem: ' + $p) 'WARN'; Write-Host ('Config problem: ' + $p) }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($url)
    try { $listener.Start() }
    catch {
        Write-DebugLog 'startup' ('Cannot listen on ' + $url + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
        Write-Host ('Cannot listen on ' + $url + ': ' + $_.Exception.Message)
        Write-Host 'Is another copy running? Use -Port (or -InternalPort behind a proxy) to pick another port.'
        exit 1
    }
    # The live state poller: runs as soon as a server account is stored and can be decrypted. A stored account that cannot be
    # decrypted (the identity changed) stops the poller and Setup shows "Server account must be entered again".
    Initialize-TlsCallbackType
    $script:Shared = New-SharedState
    $script:ServerAccount = Read-ServerAccount -BlobPath $script:ServerAccountPath -MetaPath $script:ServerAccountMetaPath
    if ($script:ServerAccount.present -and -not $script:ServerAccount.ok) {
        Write-DebugLog 'startup' ('Server account: ' + $script:ServerAccount.error + ' It must be entered again on the Setup tab.') 'WARN'
    }
    Start-StatePoller
    if ($script:ServerAccount.ok) { Set-PollerAccount -Cred $script:ServerAccount.cred; Write-DebugLog 'startup' 'Server account loaded; live state polling starts.' }
    # Behind IIS: the port HttpPlatformHandler gave us is bound by a plain TCP relay to the listener above (the lock and the
    # listener come first, so a second instance never gets this far).
    $script:Relay = $null
    if ($script:BehindProxy -and $relayPort -ne $InternalPort) {
        try { $script:Relay = Start-PortRelay -ListenPort $relayPort -TargetPort $InternalPort -Max 200 }
        catch {
            Write-DebugLog 'startup' ('Cannot bind the relay port 127.0.0.1:' + $relayPort + "`r`n" + (Format-ExceptionDetail $_.Exception)) 'ERROR'
            Write-Host ('Cannot bind the relay port 127.0.0.1:' + $relayPort + ': ' + $_.Exception.Message)
            try { $listener.Stop() } catch { }
            exit 1
        }
        Write-DebugLog 'startup' ('Relay: 127.0.0.1:' + $relayPort + ' -> 127.0.0.1:' + $InternalPort)
    }
    Write-Host ('DoorKeeper ' + $script:Version + ' listening on ' + $url + '  (Ctrl+C stops it)')
    Write-Host ('Config:    ' + $script:ConfigPath)
    Write-Host ('Debug log: ' + $script:DebugLogPath)
    Write-Host ('Audit:     ' + $script:AuditPath)
    if (-not $NoBrowser) { try { Start-Process $url } catch { Write-Host ('Could not open the browser: ' + $_.Exception.Message) } }
    try {
        while ($listener.IsListening) {
            $task = $listener.GetContextAsync()
            while (-not $task.Wait(500)) { try { Complete-FinishedJobs; Remove-ExpiredSessions } catch { } }
            Invoke-Request -Ctx $task.Result
            try { Complete-FinishedJobs } catch { }
        }
    }
    finally {
        Write-DebugLog 'shutdown' 'Console stopping.'
        Save-StateCache -MinAgeSec 0
        Stop-StatePoller
        if ($null -ne $script:Relay) { try { $script:Relay.Stop() } catch { } }
        $listener.Stop()
        $listener.Close()
        if ($null -ne $script:InstanceLock) { try { $script:InstanceLock.Close() } catch { } }
    }
}

Start-Console
