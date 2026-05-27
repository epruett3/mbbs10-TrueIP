# TRUEIP — Real Client IPs for MBBS10

When MBBS10 sits behind a reverse proxy, all users appear to connect from the proxy's IP. TRUEIP fixes this by reading the [PROXY Protocol v1 or v2](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) header that the proxy prepends, extracting the real client IP, and patching it into the BBS session.

Every existing IP consumer — sysop WHO, audit trail, IP bans — transparently sees the real IP. No changes to any other module.

## How It Works

```
Internet Client (203.0.113.42)
        |
        v
Reverse Proxy (BBSFirewall / HAProxy / nginx)
  - listens on port 23 (public)
  - prepends: PROXY TCP4 203.0.113.42 192.168.1.1 54321 2324\r\n
  - forwards to BBS port 2324
        |
        v
TRUEIP (port 2324 on BBS)
  1. Auto-detects v1 (text) vs v2 (binary) from first bytes
  2. Reads and parses the PROXY header
  3. Hands socket to telnet daemon (tntincall)
  4. Overwrites tcpipinf[usrnum].inaddr = real IP
        |
        v
BBS session sees 203.0.113.42, not 192.168.1.1
```

TRUEIP does NOT replace port 23. Normal telnet continues to work for direct/LAN connections. Block port 23 from the internet via Windows Firewall so all external traffic goes through the proxy.

## Sysop Commands

| Command | Description |
|---------|-------------|
| `/IP` | Show all active TCP/IP connections with IPs |
| `TRUEIP STATUS` | Module config, port, and connection counters |

## Install

1. Copy `TRUEIP.DLL`, `TRUEIP.MDF`, and `TRUEIP.MSG` to the BBS root directory
2. Install the module through WGSCNF/WGSETUP
3. Configure options (proxy port, trusted IPs, rate limit)
4. Block port 23 from internet via Windows Firewall
5. Restart the BBS

## Proxy Configuration

**BBSFirewall** (Node.js):
```env
PROXY_PROTOCOL_ENABLED=true
BACKEND_PORT=2324
```

**HAProxy**:
```
# v1 text format
server bbs 192.168.1.X:2324 send-proxy
# v2 binary format (also supported)
server bbs 192.168.1.X:2324 send-proxy-v2
```

**nginx stream**:
```
proxy_protocol on;
```

## Configuration Options (WGSCNF)

| Option | Default | Description |
|--------|---------|-------------|
| Proxy port | 2324 | TCP port for PROXY-wrapped connections |
| Require header | YES | Reject connections without valid PROXY header |
| Trusted IPs | (blank) | Comma-separated proxy IPs; blank = accept any |
| Max conn/sec | 10 | Rate limit; 0 = no limit |
| Debug log | NO | Write per-connection trace to TRUEIP.LOG |

## Security

| Layer | Purpose |
|-------|---------|
| Windows Firewall | Block port 23 from internet; block 2324 from non-proxy IPs |
| Trusted IP config | Defense-in-depth — reject connections from non-proxy sources |
| Require header | Reject connections without a valid PROXY header |
| Rate limiting | Protect against connection floods on the proxy port |

## Testing

Validation script (run from any machine that can reach the BBS):
```powershell
.\Test-TrueIP.ps1 -BbsHost 192.168.1.23 -Port 2324
```

Interactive session (fakes a proxy connection):
```powershell
.\Connect-TrueIP.ps1 -BbsHost 192.168.1.23 -Port 2324 -FakeIp 203.0.113.42
```

## Limitations

- IPv4 only (TCP6 headers are rejected by both v1 and v2 parsers)
- Config changes require BBS restart
- `hostdeny` IP blocking happens before TRUEIP sees the connection — per-client blocking must be done at the proxy layer

## Build

Requires Visual Studio 2022 Build Tools (x86) and the MBBS10 SDK.

```batch
build_trueip.bat
```

## License

MIT
