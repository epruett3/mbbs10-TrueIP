<#
.SYNOPSIS
    TRUEIP Proxy Protocol v1 and v2 Validation Script

.DESCRIPTION
    Tests PROXY Protocol v1 and v2 behavior against a running MBBS10 BBS with TRUEIP installed.
    Exercises eight scenarios:
      1. Valid PROXY TCP4 header (v1)          -- expects BBS login prompt
      2. No PROXY header                       -- expects rejection if require_header=YES
      3. Malformed PROXY header (v1)           -- expects rejection
      4. PROXY LOCAL (v1)                      -- expects rejection or INFO depending on config
      5. PROXY v2 TCP4 binary header           -- expects BBS login prompt
      6. PROXY v2 LOCAL (health check)         -- expects rejection
      7. PROXY v2 TCP6 (unsupported family)    -- expects rejection
      8. PROXY v2 TCP4 with TLV extensions     -- expects BBS login prompt (TLVs ignored)

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

# ---------------------------------------------------------------------------
# Helper: build a PROXY Protocol v2 magic prefix (12 bytes, constant)
# ---------------------------------------------------------------------------
function Get-ProxyV2Magic {
    return [byte[]]@(0x0D,0x0A,0x0D,0x0A,0x00,0x0D,0x0A,0x51,0x55,0x49,0x54,0x0A)
}

# ---------------------------------------------------------------------------
# Helper: convert a uint16 to 2-byte big-endian (network byte order)
# ---------------------------------------------------------------------------
function ConvertTo-NetworkUInt16 {
    param([uint16]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)   # little-endian host → big-endian network
    return $bytes
}

# ---------------------------------------------------------------------------
# Test 5: PROXY v2 TCP4 binary header
#   28-byte header: magic(12) + ver+cmd(1) + fam+proto(1) + addr_len(2)
#                   + src_addr(4) + dst_addr(4) + src_port(2) + dst_port(2)
#   Expects: BBS sends a login banner (n > 0 bytes)
#   Sysop check: Event Log or LANCE should record IP as $FakeIp
# ---------------------------------------------------------------------------
Write-Host "[Test 5] PROXY v2 TCP4 binary header..." -NoNewline
try {
    $magic    = Get-ProxyV2Magic
    $verCmd   = [byte]0x21                                              # version 2, command PROXY
    $famProto = [byte]0x11                                              # AF_INET (1), STREAM (1)
    $addrLen  = [byte[]]@(0x00, 0x0C)                                  # 12 bytes: 4+4+2+2
    $srcAddr  = [System.Net.IPAddress]::Parse($FakeIp).GetAddressBytes()
    $dstAddr  = [System.Net.IPAddress]::Parse("127.0.0.1").GetAddressBytes()
    $srcPort  = ConvertTo-NetworkUInt16 -Value 54321
    $dstPort  = ConvertTo-NetworkUInt16 -Value ([uint16]$Port)

    $header5  = $magic + $verCmd + $famProto + $addrLen + $srcAddr + $dstAddr + $srcPort + $dstPort

    ($c5, $s5) = New-TcpConnection -Host_ $BbsHost -Port_ $Port
    $s5.Write($header5, 0, $header5.Length)   # raw bytes — do NOT use ASCII encoding

    Start-Sleep -Milliseconds 1000

    ($n5, $buf5) = Read-Response -Stream $s5
    $c5.Close()

    if ($n5 -gt 0) {
        Write-Host " PASS ($n5 bytes received)" -ForegroundColor Green
        Write-Host "  Sysop check: Event Log or LANCE should show source IP: $FakeIp"
    } elseif ($n5 -eq 0) {
        Write-Host " FAIL (connection closed immediately -- BBS may have rejected v2 header)" -ForegroundColor Red
    } else {
        Write-Host " FAIL (read timeout -- BBS did not respond)" -ForegroundColor Red
    }
} catch {
    Write-Host " FAIL ($_)" -ForegroundColor Red
}

Write-Host ""

# ---------------------------------------------------------------------------
# Test 6: PROXY v2 LOCAL (health-check command)
#   16-byte header: magic(12) + 0x20 (version 2, LOCAL) + 0x00 + addr_len 0x00,0x00
#   No address payload follows.
#   Expects: connection closed (TRUEIP rejects LOCAL command)
# ---------------------------------------------------------------------------
Write-Host "[Test 6] PROXY v2 LOCAL (health check)..." -NoNewline
try {
    $magic    = Get-ProxyV2Magic
    $verCmd   = [byte]0x20   # version 2, command LOCAL
    $famProto = [byte]0x00   # unspecified
    $addrLen  = [byte[]]@(0x00, 0x00)

    $header6  = $magic + $verCmd + $famProto + $addrLen

    ($c6, $s6) = New-TcpConnection -Host_ $BbsHost -Port_ $Port -ReadTimeoutMs 3000
    $s6.Write($header6, 0, $header6.Length)

    Start-Sleep -Milliseconds 500

    ($n6, $buf6) = Read-Response -Stream $s6
    $c6.Close()

    if ($n6 -eq 0) {
        Write-Host " PASS (connection closed -- PROXY v2 LOCAL rejected)" -ForegroundColor Green
    } elseif ($n6 -lt 0) {
        Write-Host " PASS (read timed out -- likely rejected)" -ForegroundColor Green
    } else {
        Write-Host " WARN ($n6 bytes received -- expected rejection of LOCAL command)" -ForegroundColor Yellow
    }
} catch {
    Write-Host " PASS (connection refused)" -ForegroundColor Green
}

Write-Host ""

# ---------------------------------------------------------------------------
# Test 7: PROXY v2 TCP6 (unsupported address family)
#   Header: magic(12) + 0x21 (PROXY) + 0x21 (AF_INET6, STREAM) + addr_len(2) + 36 bytes of zeros
#   addr_len for IPv6 block: 16(src)+16(dst)+2(srcport)+2(dstport) = 36 => 0x00,0x24
#   Expects: connection closed (TRUEIP does not support TCP6)
# ---------------------------------------------------------------------------
Write-Host "[Test 7] PROXY v2 TCP6 (unsupported family)..." -NoNewline
try {
    $magic    = Get-ProxyV2Magic
    $verCmd   = [byte]0x21   # version 2, command PROXY
    $famProto = [byte]0x21   # AF_INET6 (2), STREAM (1)
    $addrLen  = [byte[]]@(0x00, 0x24)   # 36 bytes of IPv6 address block
    $addrData = [byte[]]::new(36)        # 36 zero bytes (any values acceptable per spec)

    $header7  = $magic + $verCmd + $famProto + $addrLen + $addrData

    ($c7, $s7) = New-TcpConnection -Host_ $BbsHost -Port_ $Port -ReadTimeoutMs 3000
    $s7.Write($header7, 0, $header7.Length)

    Start-Sleep -Milliseconds 500

    ($n7, $buf7) = Read-Response -Stream $s7
    $c7.Close()

    if ($n7 -eq 0) {
        Write-Host " PASS (connection closed -- TCP6 family rejected)" -ForegroundColor Green
    } elseif ($n7 -lt 0) {
        Write-Host " PASS (read timed out -- likely rejected)" -ForegroundColor Green
    } else {
        Write-Host " WARN ($n7 bytes received -- expected rejection of TCP6 family)" -ForegroundColor Yellow
    }
} catch {
    Write-Host " PASS (connection refused)" -ForegroundColor Green
}

Write-Host ""

# ---------------------------------------------------------------------------
# Test 8: PROXY v2 TCP4 with TLV extensions (addr_len > 12)
#   Header is identical to Test 5 except addr_len = 20 (12 addr bytes + 8 TLV bytes).
#   BBS must consume all addr_len bytes before handing the socket to the telnet daemon,
#   ignoring any trailing TLV data it does not recognise.
#   Expects: PASS -- BBS login prompt received (TLVs silently ignored)
# ---------------------------------------------------------------------------
Write-Host "[Test 8] PROXY v2 TCP4 with TLV extensions..." -NoNewline
try {
    $magic    = Get-ProxyV2Magic
    $verCmd   = [byte]0x21                                              # version 2, command PROXY
    $famProto = [byte]0x11                                              # AF_INET (1), STREAM (1)
    $addrLen  = [byte[]]@(0x00, 0x14)                                  # 20 = 12 addr + 8 TLV
    $srcAddr  = [System.Net.IPAddress]::Parse($FakeIp).GetAddressBytes()
    $dstAddr  = [System.Net.IPAddress]::Parse("127.0.0.1").GetAddressBytes()
    $srcPort  = ConvertTo-NetworkUInt16 -Value 54321
    $dstPort  = ConvertTo-NetworkUInt16 -Value ([uint16]$Port)
    $tlvData  = [byte[]]@(0x01,0x00,0x04,0xDE,0xAD,0xBE,0xEF,0x00)    # 8 bytes dummy TLV

    $header8  = $magic + $verCmd + $famProto + $addrLen + $srcAddr + $dstAddr + $srcPort + $dstPort + $tlvData

    ($c8, $s8) = New-TcpConnection -Host_ $BbsHost -Port_ $Port
    $s8.Write($header8, 0, $header8.Length)   # raw bytes

    Start-Sleep -Milliseconds 1000

    ($n8, $buf8) = Read-Response -Stream $s8
    $c8.Close()

    if ($n8 -gt 0) {
        Write-Host " PASS ($n8 bytes received -- TLV extensions correctly ignored)" -ForegroundColor Green
    } elseif ($n8 -eq 0) {
        Write-Host " FAIL (connection closed -- BBS may not be consuming full addr_len)" -ForegroundColor Red
    } else {
        Write-Host " FAIL (read timeout -- BBS did not respond)" -ForegroundColor Red
    }
} catch {
    Write-Host " FAIL ($_)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "To inspect TRUEIP log entries in the Windows Event Log:"
Write-Host "  Get-WinEvent -FilterHashtable @{ProviderName='TRUEIP'} -MaxEvents 10"
