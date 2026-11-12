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
    The socket interface is plain TCP: the password crosses the network unencrypted, as it does for every
    socket client (the Milestone plugin too).
    lock / unlock / normal / provideAccess CHANGE the door and ask for YES first (-Yes skips the question).
    Windows PowerShell 5.1.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Aeos-SocketTest.ps1 -AeosHost aeos-server -AccessPoint "aepu1:Front door"
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
    [pscredential]$Credential                                       # else asked for (AEOS socket user)
)
$ErrorActionPreference = 'Stop'
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
# Read until AEOS is quiet for QuietMs after the first bytes, or MaxMs passed.
function Read-Replies([int]$MaxMs, [int]$QuietMs = 1500) {
    $buf = New-Object byte[] 8192
    $sw = [Diagnostics.Stopwatch]::StartNew(); $last = 0; $got = $false
    while ($sw.ElapsedMilliseconds -lt $MaxMs) {
        if ($script:Stream.DataAvailable) {
            $n = $script:Stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { Write-Line 'RECV (AEOS closed the connection)'; $script:Closed = $true; return }
            Write-Line ('RECV ' + (Show-Ctl ($script:Enc.GetString($buf, 0, $n))))
            $last = $sw.ElapsedMilliseconds; $got = $true
        }
        elseif ($script:Tcp.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead) -and $script:Tcp.Client.Available -eq 0) {
            Write-Line 'RECV (AEOS closed the connection)'; $script:Closed = $true; return
        }
        elseif ($got -and ($sw.ElapsedMilliseconds - $last) -gt $QuietMs) { return }
        else { Start-Sleep -Milliseconds 50 }
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

Write-Line "AEOS socket test - $AeosHost`:$Port - function $Function - access point '$AccessPoint' - terminator $Terminator"
$script:Tcp = New-Object System.Net.Sockets.TcpClient
$script:Closed = $false
try {
    $ar = $script:Tcp.BeginConnect($AeosHost, $Port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(10000)) { throw "No connection to $AeosHost`:$Port within 10 s." }
    $script:Tcp.EndConnect($ar)
    $script:Stream = $script:Tcp.GetStream()
    Write-Line "Connected to $($script:Tcp.Client.RemoteEndPoint)"
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
