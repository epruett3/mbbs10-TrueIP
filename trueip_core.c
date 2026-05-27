/*
 * trueip_core.c -- Shared PROXY Protocol v1/v2 Core Implementation
 *
 * PURPOSE:
 *   Pure C implementation of PROXY Protocol v1 and v2 parsing, trusted-IP
 *   checking, rate limiting, config parsing, event logging, and IP formatting
 *   primitives shared by both the standalone TRUEIP MBBS10 module and the
 *   GALTCPIP clone integration layer.
 *
 * NO MBBS SDK DEPENDENCIES:
 *   This file uses only raw Winsock (ws2_32.lib) and the Windows API
 *   (for GetTickCount64 and ReportEventA).  It must compile and link cleanly
 *   without any Galacticomm/MBBS SDK headers or libraries.
 *
 * LINKING:
 *   Link with: ws2_32.lib  advapi32.lib
 *   (advapi32.lib provides ReportEventA; ws2_32.lib provides ioctlsocket,
 *    recv, inet_addr.  No user32.lib is needed — ReportEventA is in advapi32.)
 *
 * USAGE:
 *   Compile this file directly into whichever DLL needs it.  No
 *   __declspec(dllexport) is present — all functions are plain internal
 *   linkage from the perspective of the embedding DLL.
 *
 * CALLING CONVENTION:
 *   All functions use the default x86-32 calling convention (cdecl).
 *   No explicit annotation is needed on x86-32 where cdecl is the default.
 */

/*
 * trueip_core.h already includes <winsock2.h> and <windows.h> in the correct
 * order (winsock2.h first to prevent winsock.h double-inclusion), so we only
 * need the core header plus the standard C headers used by this file.
 */
#include "trueip_core.h"    /* struct trueip_config, struct trueip_rate, prototypes */

#include <stdio.h>          /* _snprintf, _vsnprintf                            */
#include <string.h>         /* strncmp, strncpy, sscanf, strlen, memcmp, memcpy */
#include <stdarg.h>         /* va_list, va_start, va_end                        */
#include <stdlib.h>         /* (reserved; included for completeness)            */

/* ---------------------------------------------------------------------------
 * TRUEIP_V2_MAGIC -- PROXY Protocol v2 binary signature (12 bytes).
 *
 * Per the HAProxy PROXY Protocol specification v2, every v2 header begins
 * with this exact sequence:
 *   \r\n\r\n\0\r\nQUIT\n
 *   0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A
 *
 * The sequence was deliberately chosen to be:
 *   - Invalid as a PROXY v1 header (does not start with "PROXY ")
 *   - Invalid as a plain-text HTTP or telnet header
 *   - Unlikely to appear at the start of any legitimate application stream
 *
 * The extern declaration is in trueip_core.h; this is the single definition.
 * --------------------------------------------------------------------------*/
const unsigned char TRUEIP_V2_MAGIC[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

/* ---------------------------------------------------------------------------
 * trueip_parse_proxy_header
 *
 * Read and parse a PROXY Protocol v1 or v2 header from an already-accepted
 * socket.  Supersedes the original trueip_parse_proxy_v1.
 *
 * ALGORITHM OVERVIEW:
 *   1. Preflight via ioctlsocket(FIONREAD): if fewer than 16 bytes are in the
 *      kernel receive buffer, return -1 immediately.  We do NOT block and do
 *      NOT call select().  The BBS scheduler is single-threaded; any blocking
 *      call in an incall handler stalls every other BBS user.
 *      NOTE: raised from 6 → 16 to satisfy both v1 ("PROXY " = 6 chars) and
 *      v2 (16-byte fixed preamble) with a single read; 16 is the tighter bound.
 *
 *   2. Read exactly 16 bytes into preamble[].  These bytes let us identify the
 *      protocol version before committing to either parse path.
 *
 *   3a. If the first 12 bytes match TRUEIP_V2_MAGIC → v2 binary parse path.
 *   3b. If the first 6 bytes are "PROXY " → v1 text parse path (preamble[6..15]
 *       are prepended into the line buffer to resume byte-at-a-time parsing).
 *   3c. Otherwise → return 0 (unrecognised; caller decides via require_header).
 *
 * V2 BINARY PATH:
 *   preamble[12]   -- version_command byte: top nibble must be 0x2 (v2).
 *                     Bottom nibble: 0x0=LOCAL, 0x1=PROXY.  LOCAL → return 0.
 *   preamble[13]   -- family_transport byte: 0x11 = AF_INET/STREAM.
 *                     Any other value (IPv6, Unix, UNSPEC) → return -1.
 *   preamble[14..15] -- addr_len (big-endian uint16).  Extracted via memcpy
 *                     to avoid strict-aliasing UB.  Capped at
 *                     PROXY_V2_ADDR_LEN_CAP; larger values → return -1.
 *                     For AF_INET/STREAM the spec mandates addr_len >= 12
 *                     (4+4 addr + 2+2 port); shorter → return -1.
 *   preamble[16..19] -- src IPv4 address (4 bytes), extracted via memcpy.
 *   Remaining (addr_len - 4) bytes starting at offset 20: read and discard
 *   so the post-header stream is clean for the caller.
 *   NOTE: preamble[] only holds 16 bytes.  The src_addr is at preamble[16],
 *   so the first 4 addr bytes are NOT in preamble[] — they are in a separate
 *   single-call recv of addr_len bytes into a stack buffer.
 *
 * V1 TEXT PATH:
 *   The 16 bytes already consumed are the start of the text header.  We copy
 *   them into line[] and continue byte-at-a-time until \r\n, then parse with
 *   sscanf exactly as before.  The algorithm is otherwise identical to the
 *   original trueip_parse_proxy_v1.
 *
 * BYTE CONSUMPTION NOTE:
 *   16 bytes are always consumed before version detection.  If neither magic
 *   is matched, those bytes are gone — same tradeoff as the original v1-only
 *   design where up to 6 bytes were consumed.  Documented and acceptable per
 *   spec: a well-behaved proxy always leads with a recognisable header.
 *
 * PARAMETERS:
 *   sock        -- the accepted socket (not yet handed to GALTNTD)
 *   real_ip_out -- receives the parsed source IP on success (return == 1)
 *
 * RETURNS:
 *    1  -- success; *real_ip_out is valid
 *    0  -- no PROXY header / PROXY LOCAL health check / v2 LOCAL command
 *   -1  -- recv error, malformed header, unsupported family, addr_len > cap
 * --------------------------------------------------------------------------*/
int
trueip_parse_proxy_header(SOCKET sock, struct in_addr *real_ip_out)
{
    /* Fixed 16-byte preamble: covers the complete v2 header or the first 16
     * bytes of a v1 text header (which we continue byte-at-a-time). */
    unsigned char   preamble[16];
    int             rc;
    int             i;

    /* V1 text-parse state — reused after copying preamble into line[]. */
    char        line[TRUEIP_MAX_HEADER + 1]; /* header max + NUL terminator     */
    int         len = 0;
    char        ch;

    char        proto[16]   = {0};
    char        src_ip[64]  = {0};
    char        dst_ip[64]  = {0};
    int         src_port    = 0;
    int         dst_port    = 0;
    int         fields;
    char       *ip_ptr;
    unsigned long addr;

    /* -- Step 1: preflight via FIONREAD ------------------------------------
     *
     * WHY ioctlsocket(FIONREAD) and NOT recvbw():
     *   recvbw() is a GALTCPIP internal that wraps ioctlsocket on the socket
     *   table managed by the BBS TCP stack.  In the clone integration context
     *   there is no GALTCPIP table; we call ioctlsocket directly instead.
     *   Both ultimately interrogate the kernel buffer — the result is identical.
     *
     * WHY 16 bytes (raised from 6):
     *   The v2 fixed preamble is exactly 16 bytes.  We always read 16 bytes
     *   upfront so we can detect either protocol in one recv() call.  16 is
     *   also more than sufficient to detect a v1 header ("PROXY " = 6 bytes).
     *
     * WHY NOT select() or blocking recv():
     *   The BBS scheduler is single-threaded.  Blocking here stalls every other
     *   user on the BBS until the proxy sends the header.  A well-behaved proxy
     *   delivers the PROXY header in the same TCP segment as the connection
     *   (or immediately after), so FIONREAD should show bytes available when
     *   incall() fires.  If the buffer is empty, something is wrong — reject. */
    {
        u_long avail = 0;
        if (ioctlsocket(sock, FIONREAD, &avail) == SOCKET_ERROR) {
            return -1;
        }
        if (avail < 16) {
            /* Fewer than 16 bytes in the buffer — cannot be a v2 header, and
             * not enough to safely read a preamble for v1 detection.  Reject. */
            return -1;
        }
    }

    /* -- Step 2: read exactly 16 bytes into preamble[] --------------------
     *
     * We use a single recv() with MSG_WAITALL semantics via a loop rather than
     * relying on MSG_WAITALL (not universally supported on Winsock for TCP).
     * FIONREAD confirmed at least 16 bytes are present, so each recv() call
     * returns immediately from the kernel buffer without blocking. */
    {
        int total = 0;
        while (total < 16) {
            rc = recv(sock, (char *)preamble + total, 16 - total, 0);
            if (rc <= 0) {
                /* Socket error or connection closed before 16 bytes arrived. */
                return -1;
            }
            total += rc;
        }
    }

    /* -- Step 3a: check for PROXY Protocol v2 magic -----------------------
     *
     * The first 12 bytes of every v2 header are TRUEIP_V2_MAGIC.  memcmp is
     * the correct tool here: it does a constant-time byte comparison with no
     * strict-aliasing concerns. */
    if (memcmp(preamble, TRUEIP_V2_MAGIC, 12) == 0) {

        /* ---- V2 BINARY PARSE PATH ---- */
        unsigned char   ver_cmd;       /* preamble[12]: version | command      */
        unsigned char   fam_trans;     /* preamble[13]: family | transport     */
        unsigned short  addr_len_net;  /* preamble[14..15]: big-endian length  */
        unsigned short  addr_len;      /* host-byte-order addr_len             */
        unsigned char   addr_buf[PROXY_V2_ADDR_LEN_CAP]; /* discard buffer    */

        ver_cmd   = preamble[12];
        fam_trans = preamble[13];

        /* Extract addr_len via memcpy to avoid strict-aliasing UB.
         * The field is big-endian (network byte order) per the v2 spec. */
        memcpy(&addr_len_net, preamble + 14, 2);
        addr_len = ntohs(addr_len_net);

        /* Check version nibble: must be 0x2 (v2).  0x1 would be v1 — should
         * never appear here since the magic already differentiates them. */
        if ((ver_cmd >> 4) != 0x2) {
            /* Unrecognised version in v2 preamble — reject. */
            return -1;
        }

        /* Command nibble: 0x0 = LOCAL (health check), 0x1 = PROXY (real conn). */
        if ((ver_cmd & 0x0F) == 0x00) {
            /* LOCAL command: health check.  No IP substitution.  Read and
             * discard the addr_len payload bytes to leave the stream clean,
             * then return 0 so the caller uses the socket's own source addr. */
            if (addr_len > 0) {
                if (addr_len > PROXY_V2_ADDR_LEN_CAP) {
                    /* Implausibly large LOCAL payload — reject. */
                    return -1;
                }
                {
                    int discarded = 0;
                    while (discarded < (int)addr_len) {
                        rc = recv(sock, (char *)addr_buf + discarded,
                                  (int)addr_len - discarded, 0);
                        if (rc <= 0) {
                            return -1;
                        }
                        discarded += rc;
                    }
                }
            }
            return 0;   /* PROXY LOCAL — caller uses socket source address */
        }

        if ((ver_cmd & 0x0F) != 0x01) {
            /* Unknown command — reject rather than guess intent. */
            return -1;
        }

        /* Family/transport: 0x11 = AF_INET (0x1) + SOCK_STREAM (0x1).
         * We are IPv4-only; AF_INET6 (0x21), AF_UNIX (0x31), UNSPEC (0x00)
         * are all rejected. */
        if (fam_trans != 0x11) {
            /* Unsupported address family or transport in v2 header — reject. */
            return -1;
        }

        /* For AF_INET/STREAM the spec requires addr_len >= 12:
         *   4 bytes src IPv4 + 4 bytes dst IPv4 + 2 bytes src port + 2 bytes dst port
         * Fewer bytes means the header is truncated. */
        if (addr_len < 12) {
            /* Truncated v2 address block — reject. */
            return -1;
        }

        /* Guard against malformed or malicious headers with oversized addr_len. */
        if (addr_len > PROXY_V2_ADDR_LEN_CAP) {
            /* addr_len exceeds PROXY_V2_ADDR_LEN_CAP — reject. */
            return -1;
        }

        /* Read addr_len bytes: [0..3]=src_addr [4..7]=dst_addr [8..9]=src_port
         * [10..11]=dst_port [12+]=optional TLVs.  We only need bytes [0..3]. */
        {
            int got = 0;
            while (got < (int)addr_len) {
                rc = recv(sock, (char *)addr_buf + got,
                          (int)addr_len - got, 0);
                if (rc <= 0) {
                    /* Socket error while reading v2 address block. */
                    return -1;
                }
                got += rc;
            }
        }

        /* Extract source IPv4 from the first 4 bytes of addr_buf.
         * memcpy avoids strict-aliasing UB when copying into s_addr (uint32). */
        memcpy(&real_ip_out->s_addr, addr_buf, 4);
        return 1;
    }

    /* -- Step 3b: check for PROXY Protocol v1 text prefix -----------------
     *
     * The 16 bytes already in preamble[] are the start of a v1 text header.
     * Copy them into line[] and continue reading byte-at-a-time until \r\n,
     * exactly as the original trueip_parse_proxy_v1 did. */
    if (memcmp(preamble, "PROXY ", 6) != 0) {
        /* First 6 bytes are neither the v2 magic nor "PROXY " — unrecognised
         * connection.  The 16 bytes are already consumed and unrecoverable.
         * Return 0; caller decides based on require_header. */
        return 0;
    }

    /* ---- V1 TEXT PARSE PATH ---- */

    /* Seed line[] with the 16 bytes already read from the socket.  These are
     * the first characters of the text header; we continue from byte 16. */
    for (i = 0; i < 16; i++) {
        line[i] = (char)preamble[i];
    }
    len = 16;

    /* Continue byte-at-a-time until \r\n or the 107-byte ceiling.
     *
     * We stop at TRUEIP_MAX_HEADER (107) bytes per the PROXY Protocol v1 spec.
     * The longest valid header is:
     *   "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n" = 56 bytes
     * The TCP6 variant is longer; 107 covers it per the RFC.
     *
     * recv() returns immediately because FIONREAD confirmed bytes are present. */
    while (len < TRUEIP_MAX_HEADER) {
        rc = recv(sock, &ch, 1, 0);
        if (rc <= 0) {
            /* Socket error or connection reset before the header was complete. */
            return -1;
        }
        if (ch == '\n' && len > 0 && line[len - 1] == '\r') {
            /* Found \r\n — strip the \r and stop. */
            line[len - 1] = '\0';
            break;
        }
        line[len++] = ch;
    }

    /* If we hit the length limit without finding \r\n, the header is malformed. */
    if (len >= TRUEIP_MAX_HEADER && !(len > 0 && line[len - 1] == '\0')) {
        line[len] = '\0';   /* ensure NUL-termination regardless */
        return -1;
    }

    /* NUL-terminate (already done in the loop above for the \r\n case). */

    /* sscanf parse into the five v1 fields. */
    fields = sscanf(line, "PROXY %15s %63s %63s %d %d",
                    proto, src_ip, dst_ip, &src_port, &dst_port);

    /* "PROXY LOCAL" is an HAProxy health-check "connection".  The spec says
     * the receiver must ignore it and not perform IP substitution.
     * Return 0 so the caller knows no real-IP was extracted. */
    if (fields >= 1 && strncmp(proto, "LOCAL", 5) == 0) {
        return 0;
    }

    if (fields < 5) {
        /* Malformed: too few fields for a TCP4 header. */
        return -1;
    }

    if (strncmp(proto, "TCP4", 4) != 0) {
        /* TCP6 and UNKNOWN are not supported in this implementation.
         * tcpipinf.inaddr is a struct in_addr (32-bit) — it cannot hold an
         * IPv6 address.  Return -1 so the caller can reject the connection. */
        return -1;
    }

    /* Strip "::ffff:" IPv4-mapped IPv6 prefix.
     *
     * Node.js running on a dual-stack socket (and some other proxies) sends
     * the source IP as "::ffff:203.0.113.42" instead of "203.0.113.42".
     * The "::ffff:" prefix is 7 characters.  Advancing the pointer past it
     * leaves a standard dotted-decimal string for inet_addr(). */
    ip_ptr = src_ip;
    if (strncmp(ip_ptr, "::ffff:", 7) == 0) {
        ip_ptr += 7;
    }

    /* Convert dotted-decimal to binary network address. */
    addr = inet_addr(ip_ptr);
    if (addr == INADDR_NONE) {
        /* INADDR_NONE means inet_addr() could not parse the string.
         * This catches "255.255.255.255" as well, but that is an invalid
         * source address in a real connection, so rejecting it is correct. */
        return -1;
    }

    /* Store result and return success. */
    real_ip_out->s_addr = addr;
    return 1;
}

/* ---------------------------------------------------------------------------
 * trueip_check_trusted
 *
 * Determine whether the connecting peer's IP is in the trusted proxy list.
 *
 * WHY we re-call inet_addr() on each check rather than pre-converting:
 *   The config is parsed once at startup and the list is short (<=8 entries).
 *   Re-calling inet_addr() is negligible cost.  Storing the pre-converted
 *   values would complicate the struct layout and the parse function without
 *   meaningful benefit at this scale.
 *
 * PARAMETERS:
 *   source -- the connecting peer's IP (from claddr.sin_addr or equivalent)
 *   cfg    -- the populated trueip_config (from trueip_parse_trusted_ips)
 *
 * RETURNS:
 *   1 -- trusted (or trusted_ip_count == 0, meaning "accept any")
 *   0 -- not in the trusted list
 * --------------------------------------------------------------------------*/
int
trueip_check_trusted(struct in_addr source, const struct trueip_config *cfg)
{
    int i;
    unsigned long entry_addr;

    /* Empty trusted list = "no restriction" — any source is accepted.
     * This is appropriate in development environments where the proxy IP is
     * dynamic.  Production deployments should always configure TRUSTIP. */
    if (cfg->trusted_ip_count == 0) {
        return 1;
    }

    for (i = 0; i < cfg->trusted_ip_count; i++) {
        entry_addr = inet_addr(cfg->trusted_ips[i]);
        /* inet_addr returns INADDR_NONE for a malformed entry; skip it.
         * Such entries should have been rejected by trueip_parse_trusted_ips,
         * but we guard here for belt-and-suspenders safety. */
        if (entry_addr == INADDR_NONE) {
            continue;
        }
        if (entry_addr == source.s_addr) {
            return 1;   /* match found */
        }
    }

    return 0;   /* no match */
}

/* ---------------------------------------------------------------------------
 * trueip_check_rate
 *
 * Enforce a sliding 1-second window rate limit on incoming connections.
 *
 * WHY GetTickCount64() and not GetTickCount():
 *   GetTickCount() wraps at ~49.7 days.  GetTickCount64() wraps after ~585
 *   million years.  The window comparison (now - rate->window_start >= 1000)
 *   would silently malfunction across a GetTickCount() wrap, causing a ~49-day
 *   window that accepts unlimited connections.  GetTickCount64() eliminates
 *   that entire class of failure.
 *
 * WHY sliding window and not token bucket:
 *   A 1-second sliding window is sufficient to prevent connection floods at
 *   the BBS scheduler level and is trivial to implement.  Token bucket adds
 *   complexity (burst allowance, refill rate) without meaningful benefit for
 *   a single-threaded BBS that processes one incall at a time.
 *
 * PARAMETERS:
 *   rate        -- the per-listener rate-limit state (modified in place)
 *   max_per_sec -- maximum connections allowed per second; <=0 = no limit
 *
 * RETURNS:
 *   1 -- connection allowed
 *   0 -- rate limit exceeded; connection should be dropped
 * --------------------------------------------------------------------------*/
int
trueip_check_rate(struct trueip_rate *rate, int max_per_sec)
{
    ULONGLONG now;

    /* max_per_sec <= 0 disables rate limiting entirely. */
    if (max_per_sec <= 0) {
        return 1;
    }

    now = GetTickCount64();

    /* If the current 1-second window has expired, start a fresh one. */
    if ((now - rate->window_start) >= 1000ULL) {
        rate->window_start = now;
        rate->window_count = 0;
    }

    /* Increment before comparing so that the first connection in a new window
     * counts as 1 (not 0), and so the check is consistent: we reject when the
     * count exceeds the limit, meaning the (max_per_sec+1)th connection is the
     * first one dropped. */
    rate->window_count++;

    if (rate->window_count > max_per_sec) {
        return 0;   /* rate limit exceeded */
    }

    return 1;
}

/* ---------------------------------------------------------------------------
 * trueip_parse_trusted_ips
 *
 * Parse a comma-separated list of IPv4 address strings into cfg->trusted_ips[].
 *
 * WHY we copy csv before tokenizing:
 *   strtok (or manual tokenization) modifies the string in place by inserting
 *   NUL bytes.  The original csv pointer may point to memory allocated by
 *   stgopt() (the MBBS SDK), which must not be modified.  We copy to a local
 *   stack buffer first.
 *
 * PARAMETERS:
 *   csv -- comma-separated IPv4 addresses, e.g. "192.168.1.1, 10.0.0.1"
 *          May be NULL or empty; in that case trusted_ip_count is set to 0.
 *   cfg -- output: populated with up to TRUEIP_MAX_TRUSTED addresses
 * --------------------------------------------------------------------------*/
void
trueip_parse_trusted_ips(const char *csv, struct trueip_config *cfg)
{
    /* Local copy — we tokenize by rewriting commas to NULs in place.
     * Sized to hold every entry at maximum length plus separators. */
    char    buf[TRUEIP_MAX_TRUSTED * TRUEIP_TRUSTED_LEN + 1];
    char   *p;
    int     count = 0;

    cfg->trusted_ip_count = 0;

    if (csv == NULL || csv[0] == '\0') {
        /* No trusted IPs configured — accept from any source.
         * trusted_ip_count == 0 signals "no restriction" in trueip_check_trusted. */
        return;
    }

    /* Copy into local buffer; truncate if somehow longer than expected. */
    strncpy(buf, csv, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    p = buf;
    while (*p != '\0' && count < TRUEIP_MAX_TRUSTED) {
        char   token[TRUEIP_TRUSTED_LEN];
        int    j = 0;
        char  *start;

        /* Skip leading whitespace and commas between tokens. */
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        start = p;

        /* Advance to the next comma or end of string. */
        while (*p != '\0' && *p != ',') {
            p++;
        }

        /* Copy the token into a local buffer so we can trim trailing whitespace
         * without modifying buf mid-parse. */
        {
            int span = (int)(p - start);
            if (span >= TRUEIP_TRUSTED_LEN) {
                span = TRUEIP_TRUSTED_LEN - 1;
            }
            strncpy(token, start, span);
            token[span] = '\0';
        }

        /* Trim trailing whitespace from the token. */
        j = (int)strlen(token);
        while (j > 0 && (token[j - 1] == ' ' || token[j - 1] == '\t')) {
            token[--j] = '\0';
        }

        if (j == 0) {
            /* Empty token after trimming — skip. */
            continue;
        }

        /* Store in cfg.  We do not validate the IP here; trueip_check_trusted
         * skips INADDR_NONE entries if a bad string somehow gets through. */
        strncpy(cfg->trusted_ips[count], token, sizeof(cfg->trusted_ips[count]) - 1);
        cfg->trusted_ips[count][sizeof(cfg->trusted_ips[count]) - 1] = '\0';
        count++;
    }

    cfg->trusted_ip_count = count;
}

/* ---------------------------------------------------------------------------
 * trueip_log_event
 *
 * Write a formatted message to a Windows Event Log source handle.
 *
 * WHY ReportEventA instead of WriteEventLog or other APIs:
 *   ReportEventA is the standard Win32 API for writing Application Event Log
 *   entries.  It requires a source handle from RegisterEventSourceA().
 *   We use LPCSTR* (array of pointers) as required by the API's strings
 *   parameter — it is NOT a single char pointer, but an array of them.
 *
 * PARAMETERS:
 *   hLog -- handle from RegisterEventSourceA().  If NULL, returns silently.
 *   type -- EVENTLOG_INFORMATION_TYPE / EVENTLOG_WARNING_TYPE /
 *           EVENTLOG_ERROR_TYPE  (from winnt.h via windows.h)
 *   fmt  -- printf-style format string; total output capped at 511 chars.
 * --------------------------------------------------------------------------*/
void
trueip_log_event(HANDLE hLog, WORD type, const char *fmt, ...)
{
    char    msg[512];
    va_list ap;
    /* ReportEventA's lpStrings parameter is an array of LPCSTR pointers,
     * not a single string.  We wrap our single message in a 1-element array. */
    const char *strings[1];

    if (hLog == NULL) {
        return;
    }

    va_start(ap, fmt);
    _vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
    va_end(ap);
    msg[sizeof(msg) - 1] = '\0';

    strings[0] = msg;

    ReportEventA(
        hLog,       /* handle from RegisterEventSourceA()                    */
        type,       /* event type: INFORMATION, WARNING, or ERROR            */
        0,          /* category: 0 = none (no .mc category file used)        */
        0,          /* event ID: 0 = generic (no .mc message file used)      */
        NULL,       /* user SID: NULL = system account                       */
        1,          /* number of strings in the strings[] array              */
        0,          /* size of binary data (none)                            */
        strings,    /* array of message strings (our single formatted msg)   */
        NULL        /* binary data pointer (none)                            */
    );
}

/* ---------------------------------------------------------------------------
 * trueip_format_ip
 *
 * Format a struct in_addr as a dotted-decimal string into a caller-supplied
 * buffer.
 *
 * WHY NOT inet_ntoa():
 *   inet_ntoa() returns a pointer to a static internal Winsock buffer.  If
 *   two calls appear in a single printf/log statement — e.g. logging both the
 *   real IP and the proxy IP — the second call overwrites the buffer before
 *   the format string is evaluated, producing two identical (wrong) values in
 *   the output.  Writing into the caller's buffer eliminates this trap.
 *
 * WHY byte-by-byte extraction via unsigned char*:
 *   in_addr.s_addr is stored in network byte order (big-endian).  Casting to
 *   unsigned char* gives us the individual octets in the wire order regardless
 *   of host endianness, which is exactly what we want for dotted-decimal output.
 *
 * PARAMETERS:
 *   addr    -- the IP address to format
 *   buf     -- caller-supplied output buffer
 *   bufsize -- size of buf in bytes; output is always NUL-terminated
 * --------------------------------------------------------------------------*/
void
trueip_format_ip(struct in_addr addr, char *buf, int bufsize)
{
    /* Cast to unsigned char* to extract individual octets in network order.
     * b[0] = first octet (highest in dotted notation), ..., b[3] = last. */
    unsigned char *b = (unsigned char *)&addr.s_addr;

    if (buf == NULL || bufsize <= 0) {
        return;
    }

    _snprintf(buf, (size_t)bufsize, "%u.%u.%u.%u",
              (unsigned)b[0], (unsigned)b[1],
              (unsigned)b[2], (unsigned)b[3]);

    /* _snprintf does not guarantee NUL termination if the buffer is exactly
     * full.  Force it to ensure the caller always gets a valid C string. */
    buf[bufsize - 1] = '\0';
}

/* end of trueip_core.c */
