TRUEIP - Real Client IP via PROXY Protocol
Version 1.0.0
Developer: Realmforge
===========================================================================

WHAT TRUEIP DOES
----------------
TRUEIP adds PROXY Protocol v1 support to MBBS10 so the BBS can see the
real client IP address when running behind a reverse proxy such as HAProxy,
nginx, or BBSFirewall. Without it, all incoming users appear to connect from
the proxy's IP; with it, the BBS session record and host-deny list reflect
the actual remote address. TRUEIP opens a second listener port (default 2324)
for PROXY-wrapped connections while leaving the normal telnet port (23)
completely unchanged.


FILES INCLUDED
--------------
  TRUEIP.DLL    Main module binary. Copy to your MBBS10 BBS root.
  TRUEIP.MDF    Module descriptor. Copy to your MBBS10 BBS root.
  TRUEIP.MSG    Sysop configuration strings. Copy to your MBBS10 BBS root.
  Test-TrueIP.ps1   PowerShell validation script (see VALIDATION below).
  README.txt    This file.


INSTALL STEPS
-------------
1. COPY FILES
   Copy TRUEIP.DLL, TRUEIP.MDF, and TRUEIP.MSG to your BBS root
   (e.g., C:\BBSV10\).

2. REGISTER THE MODULE (WGSCNF)
   Boot the BBS to a maintenance shell or use WGSCNF.EXE to add TRUEIP
   to the module list. TRUEIP has no dependencies and no Btrieve files.

3. CONFIGURE (WGSCNF / Sysop menu)
   Run WGSCNF and navigate to the TRUEIP configuration section:

     TPORT    - Proxy listener port (default 2324). Must not conflict with
                any existing service. Open this port in your firewall.

     REQHDR   - Whether to reject connections without a PROXY header.
                Set YES in production behind a proxy. NO allows direct
                connections (no IP substitution occurs for those sessions).

     TRUSTIP  - Comma-separated list of trusted proxy IP addresses.
                Example: 10.0.0.1,192.168.1.1
                Leave blank to accept PROXY headers from any source
                (only safe on a private LAN).

     MAXRATE  - Maximum new connections per second on the proxy port.
                Default 10. Set 0 to disable rate limiting.

     LOGEN    - Enable debug log to TRUEIP.LOG. Use only for troubleshooting;
                disable in production.

     LOGMAX   - Log rotation size in KB (active only when LOGEN=YES).

4. OPEN FIREWALL PORT
   Allow inbound TCP on the proxy listener port (default 2324) from your
   proxy server's IP only. Block it from the public internet.

   Windows Firewall example:
     netsh advfirewall firewall add rule name="TRUEIP Proxy Port" ^
       protocol=TCP dir=in localport=2324 action=allow ^
       remoteip=<proxy_LAN_IP>

5. BOOT THE BBS
   Start MBBS10 normally. TRUEIP logs its startup status to SYSLOG.DAT.
   Confirm you see a line similar to:
     [TRUEIP] Proxy listener ready on port 2324

6. VALIDATE
   Run the included Test-TrueIP.ps1 from the BBS host:
     powershell -ExecutionPolicy Bypass -File .\Test-TrueIP.ps1
   All three tiers must pass before directing proxy traffic.


BBSFIREWALL INTEGRATION
-----------------------
BBSFirewall (or any HAProxy/nginx setup) must be configured to send
PROXY Protocol v1 headers on the backend connection.

For BBSFirewall, set the following in your .env file:

  PROXY_PROTOCOL_ENABLED=true
  BACKEND_PORT=2324

This tells BBSFirewall to connect to port 2324 (instead of 23) and prepend
the PROXY v1 header (e.g., "PROXY TCP4 1.2.3.4 10.0.0.1 54321 2324\r\n")
before relaying the client data.

For HAProxy, add to your backend section:
  server bbs 127.0.0.1:2324 send-proxy

For nginx (stream module):
  proxy_pass 127.0.0.1:2324;
  proxy_protocol on;

The normal telnet port (23) on the BBS should be firewalled from the public
internet; all public traffic should arrive via the proxy on port 2324.


SYSOP COMMANDS
--------------
The following command is available to sysops at the MBBS10 sysop prompt:

  TRUEIP STATUS
    Displays the current module state including:
    - Proxy listener port and status (running / stopped)
    - Total connections accepted on the proxy port since last boot
    - Connections rejected (no PROXY header, if REQHDR=YES)
    - Connections rejected (rate limit)
    - Current trusted-proxy IP list


TROUBLESHOOTING QUICK REFERENCE
--------------------------------
1. "TRUEIP.DLL not found" in SYSLOG.DAT
   The DLL was not copied to the BBS root, or the MDF was not registered.
   Verify all three files (DLL, MDF, MSG) are in C:\BBSV10\ and WGSCNF
   shows TRUEIP in the module list.

2. All users still show the proxy's IP, not the real client IP
   Check that your reverse proxy is actually sending PROXY headers to port
   2324 (not port 23). Verify BACKEND_PORT=2324 in BBSFirewall .env, or
   that "send-proxy" is in your HAProxy backend stanza.

3. "Connection refused" on port 2324
   TRUEIP may have failed to bind the port (already in use, or firewall
   blocking loopback). Check SYSLOG.DAT for bind errors. Try TRUEIP STATUS
   from the sysop prompt to confirm the listener is running.

4. REQHDR=YES but direct connections are being rejected unexpectedly
   A normal telnet client hitting port 2324 will be rejected because it
   sends no PROXY header. This is correct behavior. Port 23 remains fully
   open for direct telnet. Do not advertise port 2324 as the public port.

5. TRUEIP.LOG grows without bound
   Set LOGEN=NO in WGSCNF to disable logging, or set LOGMAX to a nonzero
   value for automatic rotation. One .BAK file is kept on rotation.


KNOWN LIMITATIONS
-----------------
- PROXY Protocol v1 only. PROXY Protocol v2 (binary) is not supported.
  Configure your proxy to use "send-proxy" (v1), not "send-proxy-v2".

- IPv4 only. PROXY lines carrying IPv6 addresses (PROXY TCP6) are rejected
  with a log entry. IPv6 client support is planned for a future release.

- Host-deny bypass window. The real IP is patched into the session record
  after the PROXY header is parsed, which occurs after the initial TCP
  accept. There is a brief window before the patch where the host-deny
  check runs against the proxy's IP rather than the client's IP. On a
  private LAN proxy this is harmless; the proxy IP is already trusted.

- Audit trail cosmetic gap. The MBBS10 audit record for the connection-open
  event is written before TRUEIP patches the IP. The syslog and subsequent
  audit events use the correct real IP; only the first connect-open entry
  may show the proxy IP.


VERSION HISTORY
---------------
1.0.0  Initial release. PROXY Protocol v1, IPv4, single listener port,
       rate limiting, trusted-IP filter, debug log with rotation,
       TRUEIP STATUS sysop command.
