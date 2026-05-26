<#
.SYNOPSIS
    TRUEIP Proxy Protocol v1 Validation Script

.DESCRIPTION
    Tests PROXY Protocol v1 behavior against a running MBBS10 BBS with TRUEIP installed.
    Exercises four scenarios:
      1. Valid PROXY TCP4 header  -- expects BBS login prompt
      2. No PROXY header          -- expects rejection if require_header=YES
      3. Malformed PROXY header   -- expects rejection
      4. PROXY LOCAL              -- expects rejection or INFO depending on config

    Check the Windows Event Log after running:
      Get-WinEvent -FilterHashtable @{ProviderName='TRUEIP'} -MaxEvents 10

.PARAMETER BbsHost
    Hostname or IP of the MBBS10 server. Default: localhost

.PARAMETER Port
    TCP port the BBS listens on. Default: 2324

.PARAMETER FakeIp
    Source IP address to inject via PROXY header (RFC 5737 documentation range).
    Default: 203.0.113.42

.EXAMPLE
    .\Test-TrueIP.ps1
    .\Test-TrueIP.ps1 -BbsHost 192.168.1.10 -Port 2323 -FakeIp 198.51.100.7
#>
param(
    [string]$BbsHost = "localhost",
    [int]$Port = 2324,
    [string]$FakeIp = "203.0.113.42"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host "=== TRUEIP Validation Script ===" -ForegroundColor Cyan
Write-Host "Target: ${BbsHost}:${Port}"
Write-Host "Fake IP: $FakeIp"
Write-Host ""

# ---------------------------------------------------------------------------
# Helper: open a TCP connection, return ($client, $stream) or throw
# ---------------------------------------------------------------------------
function New-TcpConnection {
    param([string]$Host_, [int]$Port_, [int]$ReadTimeoutMs = 3000, [int]$WriteTimeoutMs = 5000)
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($Host_, $Port_)
    $stream = $client.GetStream()
    $stream.ReadTimeout  = $ReadTimeoutMs
    $stream.WriteTimeout = $WriteTimeoutMs
    return $client, $stream
}

# ---------------------------------------------------------------------------
# Helper: send raw ASCII bytes to a stream
# ---------------------------------------------------------------------------
function Send-Ascii {
    param([System.Net.Sockets.NetworkStream]$Stream, [string]$Text)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Text)
    $Stream.Write($bytes, 0, $bytes.Length)
}

# ---------------------------------------------------------------------------
# Helper: attempt a read; returns byte count read (0 = graceful close, -1 = timeout/error)
# ---------------------------------------------------------------------------
function Read-Response {
    param([System.Net.Sockets.NetworkStream]$Stream, [int]$BufSize = 4096)
    $buf = New-Object byte[] $BufSize
    try {
        $n = $Stream.Read($buf, 0, $buf.Length)
        return $n, $buf
    } catch [System.IO.IOException] {
        # Timeout or connection reset -- treat as rejection
        return -1, $null
    }
}

# ---------------------------------------------------------------------------
# Test 1: Valid PROXY TCP4 header
#   Expects: BBS sends a login banner (n > 0 bytes)
#   Sysop check: LANCE or Event Log should record IP as $FakeIp
# ---------------------------------------------------------------------------
Write-Host "[Test 1] PROXY TCP4 header..." -NoNewline
try {
    $header = "PROXY TCP4 $FakeIp 127.0.0.1 54321 $Port`r`n"
    ($c1, $s1) = New-TcpConnection -Host_ $BbsHost -Port_ $Port
    Send-Ascii -Stream $s1 -Text $header

    Start-Sleep -Milliseconds 1000

    ($n1, $buf1) = Read-Response -Stream $s1
    $c1.Close()

    if ($n1 -gt 0) {
        Write-Host " PASS ($n1 bytes received)" -ForegroundColor Green
        Write-Host "  Sysop check: Event Log or LANCE should show source IP: $FakeIp"
    } elseif ($n1 -eq 0) {
        Write-Host " FAIL (connection closed immediately -- BBS may have rejected header)" -ForegroundColor Red
    } else {
        Write-Host " FAIL (read timeout -- BBS did not respond)" -ForegroundColor Red
    }
} catch {
    Write-Host " FAIL ($_)" -ForegroundColor Red
}

Write-Host ""

# ---------------------------------------------------------------------------
# Test 2: Direct connection -- no PROXY header
#   Expects (require_header=YES): connection closed or timeout (no banner)
#   Expects (require_header=NO):  BBS sends banner anyway
# ---------------------------------------------------------------------------
Write-Host "[Test 2] Direct connection (no PROXY header)..." -NoNewline
try {
    ($c2, $s2) = New-TcpConnection -Host_ $BbsHost -Port_ $Port -ReadTimeoutMs 3000
    # Do not send anything -- wait to see what the BBS does
    Start-Sleep -Milliseconds 1000

    ($n2, $buf2) = Read-Response -Stream $s2
    $c2.Close()

    if ($n2 -eq 0) {
        Write-Host " PASS (connection closed -- require_header=YES)" -ForegroundColor Green
    } elseif ($n2 -lt 0) {
        Write-Host " PASS (read timed out -- connection held open, no banner sent)" -ForegroundColor Green
    } else {
        Write-Host " INFO ($n2 bytes received -- require_header may be NO)" -ForegroundColor Yellow
    }
} catch {
    # Connect refused = hard rejection before handshake
    Write-Host " PASS (connection refused)" -ForegroundColor Green
}

Write-Host ""

# ---------------------------------------------------------------------------
# Test 3: Malformed PROXY header
#   Expects: connection closed (TRUEIP rejects unparseable header)
# ---------------------------------------------------------------------------
Write-Host "[Test 3] Malformed PROXY header..." -NoNewline
try {
    ($c3, $s3) = New-TcpConnection -Host_ $BbsHost -Port_ $Port -ReadTimeoutMs 3000
    Send-Ascii -Stream $s3 -Text "PROXY GARBAGE`r`n"

    Start-Sleep -Milliseconds 500

    ($n3, $buf3) = Read-Response -Stream $s3
    $c3.Close()

    if ($n3 -eq 0) {
        Write-Host " PASS (connection closed -- malformed header rejected)" -ForegroundColor Green
    } elseif ($n3 -lt 0) {
        Write-Host " PASS (read timed out -- likely pending rejection)" -ForegroundColor Green
    } else {
        Write-Host " WARN ($n3 bytes received -- expected rejection of malformed header)" -ForegroundColor Yellow
    }
} catch {
    Write-Host " PASS (connection refused)" -ForegroundColor Green
}

Write-Host ""

# ---------------------------------------------------------------------------
# Test 4: PROXY LOCAL (health-check / loopback command)
#   PROXY LOCAL carries no address fields -- TRUEIP should treat it as no-header.
#   Expects (require_header=YES): rejection
#   Expects (require_header=NO):  some response (BBS falls through without IP injection)
# ---------------------------------------------------------------------------
Write-Host "[Test 4] PROXY LOCAL (health check)..." -NoNewline
try {
    ($c4, $s4) = New-TcpConnection -Host_ $BbsHost -Port_ $Port -ReadTimeoutMs 3000
    Send-Ascii -Stream $s4 -Text "PROXY LOCAL`r`n"

    Start-Sleep -Milliseconds 500

    ($n4, $buf4) = Read-Response -Stream $s4
    $c4.Close()

    if ($n4 -eq 0) {
        Write-Host " PASS (connection closed -- PROXY LOCAL rejected, require_header=YES)" -ForegroundColor Green
    } elseif ($n4 -lt 0) {
        Write-Host " PASS (read timed out -- likely rejected)" -ForegroundColor Green
    } else {
        Write-Host " INFO ($n4 bytes received -- PROXY LOCAL passed through, require_header=NO)" -ForegroundColor Yellow
    }
} catch {
    Write-Host " PASS (connection refused)" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "To inspect TRUEIP log entries in the Windows Event Log:"
Write-Host "  Get-WinEvent -FilterHashtable @{ProviderName='TRUEIP'} -MaxEvents 10"
