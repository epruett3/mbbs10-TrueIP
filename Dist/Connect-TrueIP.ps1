<#
.SYNOPSIS
    Interactive telnet session through TRUEIP's proxy port.
    Sends a PROXY Protocol v1 header, then lets you interact with the BBS.

.DESCRIPTION
    Fakes what a reverse proxy (BBSFirewall, HAProxy) would do:
    connects to the TRUEIP proxy port, sends the PROXY header with a
    fake client IP, then relays BBS output to your console and your
    keyboard input to the BBS.

    Use TRUEIP WHO on the sysop console to verify the fake IP appears.

.PARAMETER BbsHost
    BBS hostname or IP (default: 192.168.1.23)

.PARAMETER Port
    TRUEIP proxy port (default: 2324)

.PARAMETER FakeIp
    The "real client IP" to put in the PROXY header (default: 203.0.113.42)

.EXAMPLE
    .\Connect-TrueIP.ps1
    .\Connect-TrueIP.ps1 -FakeIp 10.20.30.40
#>
param(
    [string]$BbsHost = "192.168.1.23",
    [int]$Port = 2324,
    [string]$FakeIp = "203.0.113.42"
)

Write-Host "Connecting to ${BbsHost}:${Port} as ${FakeIp}..." -ForegroundColor Cyan
Write-Host "Press Ctrl-C to disconnect." -ForegroundColor DarkGray
Write-Host ""

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($BbsHost, $Port)
$stream = $client.GetStream()
$stream.ReadTimeout = 100

# Send PROXY Protocol v1 header
$header = "PROXY TCP4 $FakeIp $BbsHost 54321 $Port`r`n"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($header)
$stream.Write($bytes, 0, $bytes.Length)

$buf = New-Object byte[] 4096
$enc = [System.Text.Encoding]::ASCII

try {
    while ($client.Connected) {
        # Read from BBS and display
        try {
            while ($stream.DataAvailable) {
                $n = $stream.Read($buf, 0, $buf.Length)
                if ($n -gt 0) {
                    $text = $enc.GetString($buf, 0, $n)
                    # Strip ANSI escape codes for cleaner display (optional)
                    Write-Host $text -NoNewline
                }
            }
        } catch [System.IO.IOException] {
            # ReadTimeout — no data available, that's fine
        }

        # Read keyboard and send to BBS
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter') {
                $stream.Write([byte[]]@(13, 10), 0, 2)
            } else {
                $ch = [byte][char]$key.KeyChar
                $stream.Write([byte[]]@($ch), 0, 1)
            }
        }

        Start-Sleep -Milliseconds 20
    }
} finally {
    $client.Close()
    Write-Host ""
    Write-Host "Disconnected." -ForegroundColor Yellow
}
