<#
.SYNOPSIS
    Talks to the AEOS socket interface (TCP 8035) once and shows every byte AEOS sends back: log in, enable
    commands, send ONE door function, listen. Default function isLocked only asks for the door state.
.DESCRIPTION
    Sequence: connect -> login(<user>,<password>); -> setRmiCommandConnection(true); ->
    execute(<function>,"<access point>"); -> listen -ListenSec seconds -> close.
    <access point> is "<HostName>:<Name>" exactly as the AEOS log shows it (findAccessPoint returns both).
    Every line sent and received is printed with control characters made visible (<CR> <LF> <ETX>) and saved
    as aeos-socket-<time>.txt next to this script. The password is never printed or saved (shown as ****).
    TLS by default: an AEOS 2023.2 socket interface answered a plain-text login with a TLS alert (bytes
    15 03 03 00 02 02 0A) and closed. -SkipTlsCheck accepts a self-signed AEOS certificate; the certificate
    seen is always logged. -Plain only for a socket interface without TLS (the password then crosses the
    network unencrypted).
    lock / unlock / normal / provideAccess CHANGE the door and ask for YES first (-Yes skips the question).
    Windows PowerShell 5.1.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Aeos-SocketTest.ps1 -AeosHost aeos-server -AccessPoint "aepu1:Front door" -SkipTlsCheck
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Aeos-SocketTest.ps1 -AeosHost aeos-server -AccessPoint "aepu1:Front door" -Function provideAccess
#>
param(
    [Parameter(Mandatory = $true)][string]$AeosHost,                # AEOS server name or IP
    [int]$Port = 8035,                                              # socket interface port
    [Parameter(Mandatory = $true)][string]$AccessPoint,             # "<HostName>:<Name>"
    [ValidateSet('isLocked', 'isUnlocked', 'lock', 'unlock', 'normal', 'provideAccess')][string]$Function = 'isLocked',
    [ValidateSet('CRLF', 'LF', 'None')][string]$Terminator = 'CRLF', # what follows each ';'
    [switch]$UseExecuteArgs,                                        # send executeArgs(fn,[],"ap"); instead of execute(fn,"ap");
    [switch]$NoRmiCommand,                                          # do not send setRmiCommandConnection(true);
    [int]$ListenSec = 5,                                            # how long to listen after the command
    [switch]$Yes,                                                   # no YES question for door-changing functions
    [switch]$SkipTlsCheck,                                          # accept a self-signed AEOS certificate
    [switch]$Plain,                                                 # no TLS (only if the socket interface has none)
    [pscredential]$Credential                                       # else asked for (AEOS socket user)
)
$ErrorActionPreference = 'Stop'
if (-not ('AeosSocketTls' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class AeosSocketTls
{
    public static bool Skip;
    public static string Last = "";
    public static RemoteCertificateValidationCallback Callback
    {
        get { return new RemoteCertificateValidationCallback(Validate); }
    }
    private static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        if (cert == null) { Last = "no certificate, errors: " + errors; }
        else
        {
            X509Certificate2 c2 = new X509Certificate2(cert);
            Last = "subject " + c2.Subject + " | issuer " + c2.Issuer + " | thumbprint " + c2.Thumbprint +
                   " | valid " + c2.NotBefore.ToString("yyyy-MM-dd") + " to " + c2.NotAfter.ToString("yyyy-MM-dd") + " | errors: " + errors;
        }
        return Skip || errors == SslPolicyErrors.None;
    }
}
'@
}
[AeosSocketTls]::Skip = [bool]$SkipTlsCheck
$script:Log = New-Object System.Collections.Generic.List[string]
$script:Enc = New-Object System.Text.UTF8Encoding($false)
$script:Term = @{ CRLF = "`r`n"; LF = "`n"; None = '' }[$Terminator]

function Show-Ctl([string]$T) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $T.ToCharArray()) {
        $c = [int]$ch
        if ($c -eq 13) { [void]$sb.Append('<CR>') } elseif ($c -eq 10) { [void]$sb.Append('<LF>') }
        elseif ($c -eq 3) { [void]$sb.Append('<ETX>') } elseif ($c -lt 32) { [void]$sb.Append(('<0x{0:X2}>' -f $c)) }
        else { [void]$sb.Append($ch) }
    }
    $sb.ToString()
}
function Write-Line([string]$T) { $l = (Get-Date -Format 'HH:mm:ss.fff') + ' ' + $T; $script:Log.Add($l); Write-Host $l }
function Send-Text([string]$Text, [string]$Shown) {
    $b = $script:Enc.GetBytes($Text + $script:Term)
    $script:Stream.Write($b, 0, $b.Length); $script:Stream.Flush()
    Write-Line ('SEND ' + (Show-Ctl ($Shown + $script:Term)))
}
# Read until AEOS is quiet for QuietMs after the first bytes, or MaxMs passed. One read stays pending
# between calls (BeginRead), which works the same for the TLS stream and the plain one.
$script:Buf = New-Object byte[] 8192
$script:Pending = $null
function Read-Replies([int]$MaxMs, [int]$QuietMs = 1500) {
    $sw = [Diagnostics.Stopwatch]::StartNew(); $last = 0; $got = $false
    while ($true) {
        $remain = $MaxMs - $sw.ElapsedMilliseconds
        if ($got) { $remain = [Math]::Min($remain, $QuietMs - ($sw.ElapsedMilliseconds - $last)) }
        if ($remain -le 0) { break }
        if (-not $script:Pending) { $script:Pending = $script:Stream.BeginRead($script:Buf, 0, $script:Buf.Length, $null, $null) }
        if (-not $script:Pending.AsyncWaitHandle.WaitOne([int]$remain)) { continue }
        try { $n = $script:Stream.EndRead($script:Pending) }
        catch { $script:Pending = $null; Write-Line ('RECV (read failed: ' + $_.Exception.Message + ')'); $script:Closed = $true; return }
        $script:Pending = $null
        if ($n -le 0) { Write-Line 'RECV (AEOS closed the connection)'; $script:Closed = $true; return }
        Write-Line ('RECV ' + (Show-Ctl ($script:Enc.GetString($script:Buf, 0, $n))))
        if ($Plain -and $n -ge 3 -and $script:Buf[0] -eq 0x15 -and $script:Buf[1] -eq 3) {
            Write-Line 'NOTE this is a TLS alert: the socket interface expects TLS - run again without -Plain.'
        }
        $last = $sw.ElapsedMilliseconds; $got = $true
    }
    if (-not $got) { Write-Line "RECV (nothing within $MaxMs ms)" }
}

$changes = @('lock', 'unlock', 'normal', 'provideAccess') -contains $Function
if ($changes -and -not $Yes) {
    $a = Read-Host "'$Function' CHANGES door '$AccessPoint'. Type YES to send it"
    if ($a -cne 'YES') { 'Nothing sent.'; return }
}
if (-not $Credential) { $Credential = Get-Credential -Message 'AEOS socket user (the account the Milestone plugin uses)' }
$nc = $Credential.GetNetworkCredential()
if ($nc.Password -match '[,);]' -or $nc.UserName -match '[,);]') { Write-Host 'Note: the user or password contains , ) or ; - AEOS may read the login wrongly.' }
$cmd = if ($UseExecuteArgs) { 'executeArgs(' + $Function + ',[],"' + $AccessPoint + '");' } else { 'execute(' + $Function + ',"' + $AccessPoint + '");' }

Write-Line "AEOS socket test - $AeosHost`:$Port - $(if($Plain){'PLAIN TCP'}else{'TLS'}) - function $Function - access point '$AccessPoint' - terminator $Terminator"
$script:Tcp = New-Object System.Net.Sockets.TcpClient
$script:Closed = $false
try {
    $ar = $script:Tcp.BeginConnect($AeosHost, $Port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(10000)) { throw "No connection to $AeosHost`:$Port within 10 s." }
    $script:Tcp.EndConnect($ar)
    Write-Line "Connected to $($script:Tcp.Client.RemoteEndPoint)"
    if ($Plain) { $script:Stream = $script:Tcp.GetStream() }
    else {
        $ssl = New-Object System.Net.Security.SslStream($script:Tcp.GetStream(), $false, [AeosSocketTls]::Callback)
        try { $ssl.AuthenticateAsClient($AeosHost, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false) }
        catch {
            $m = $_.Exception.Message; $ie = $_.Exception.InnerException; while ($ie) { $m += ' -> ' + $ie.Message; $ie = $ie.InnerException }
            if ([AeosSocketTls]::Last) { Write-Line ('TLS certificate: ' + [AeosSocketTls]::Last) }
            throw "TLS handshake failed: $m$(if(-not $SkipTlsCheck){' (self-signed AEOS certificate? add -SkipTlsCheck)'})"
        }
        Write-Line ('TLS ' + $ssl.SslProtocol + ', cipher ' + $ssl.CipherAlgorithm + '/' + $ssl.CipherStrength + ' - certificate: ' + [AeosSocketTls]::Last)
        $script:Stream = $ssl
    }
    Read-Replies 2000 500                                           # a greeting, if AEOS sends one
    Send-Text ('login(' + $nc.UserName + ',' + $nc.Password + ');') ('login(' + $nc.UserName + ',****);')
    Read-Replies 5000
    if (-not $script:Closed -and -not $NoRmiCommand) { Send-Text 'setRmiCommandConnection(true);' 'setRmiCommandConnection(true);'; Read-Replies 5000 }
    if (-not $script:Closed) { Send-Text $cmd $cmd; Read-Replies ($ListenSec * 1000) }
}
catch { Write-Line ('ERROR ' + $_.Exception.Message) }
finally { $script:Tcp.Close(); Write-Line 'Closed.' }
$file = Join-Path $PSScriptRoot ('aeos-socket-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
try { Set-Content -LiteralPath $file -Value $script:Log -Encoding UTF8; "Saved to $file" } catch { "Not saved: $($_.Exception.Message)" }
