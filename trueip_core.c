/*
 * trueip_core.c -- Shared PROXY Protocol v1 Core Implementation
 *
 * PURPOSE:
 *   Pure C implementation of the PROXY Protocol v1 parsing, trusted-IP
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
#include <string.h>         /* strncmp, strncpy, sscanf, strlen                 */
#include <stdarg.h>         /* va_list, va_start, va_end                        */
#include <stdlib.h>         /* (reserved; included for completeness)            */

/* ---------------------------------------------------------------------------
 * trueip_parse_proxy_v1
 *
 * Read and parse a PROXY Protocol v1 header from an already-accepted socket.
 *
 * ALGORITHM OVERVIEW:
 *   1. Preflight via ioctlsocket(FIONREAD): if fewer than 6 bytes are in the
 *      kernel receive buffer, return -1 immediately.  We do NOT block and do
 *      NOT call select().  The BBS scheduler is single-threaded; any blocking
 *      call in an incall handler stalls every other BBS user.
 *
 *   2. Receive one byte at a time until \r\n is found or the 107-byte limit
 *      is reached.  recv() returns immediately from the kernel buffer because
 *      FIONREAD confirmed bytes are present.  Byte-at-a-time avoids consuming
 *      post-header bytes (telnet IAC negotiation) that GALTNTD needs to read.
 *
 *   3. Null-terminate and strip the trailing \r\n.
 *
 *   4. Check the "PROXY " prefix (6 bytes).  If absent, return 0 (direct
 *      connection — no bytes have been consumed at this point... actually
 *      bytes HAVE been consumed up to where the prefix mismatch was detected.
 *      See NOTE below on the direct-connection case).
 *
 *   5. sscanf parse into proto/src_ip/dst_ip/src_port/dst_port.
 *      Require exactly 5 fields for TCP4; fewer means LOCAL or malformed.
 *
 *   6. "LOCAL" (1 field) → return 0 (HAProxy health check, no IP substitution).
 *      Non-TCP4 → return -1 (TCP6 unsupported; tcpipinf.inaddr is 32-bit only).
 *
 *   7. Strip "::ffff:" prefix from src_ip if present.  Node.js dual-stack
 *      sockets send IPv4-mapped IPv6 addresses ("::ffff:203.0.113.42").
 *      Stripping the prefix produces a standard dotted-decimal string that
 *      inet_addr() can parse.
 *
 *   8. inet_addr() conversion.  INADDR_NONE (0xFFFFFFFF) → malformed → -1.
 *
 *   9. Store in *real_ip_out, return 1.
 *
 * NOTE on step 4 and byte consumption:
 *   In the byte-at-a-time approach, bytes are consumed from the kernel buffer
 *   as we read.  If the prefix does not match (return 0 case), those bytes are
 *   already gone.  Callers that pass require_header=NO in the direct-connection
 *   path should be aware of this.  The MSG_PEEK approach in trueip.c avoids
 *   this by peeking first, but this core function uses byte-at-a-time per the
 *   spec.  In practice, a valid PROXY-protocol endpoint always sends the header,
 *   so the return-0 case here is only the PROXY LOCAL health-check path.
 *
 * PARAMETERS:
 *   sock        -- the accepted socket (not yet handed to GALTNTD)
 *   real_ip_out -- receives the parsed source IP on success (return == 1)
 *
 * RETURNS:
 *    1  -- success; *real_ip_out is valid
 *    0  -- no PROXY header / PROXY LOCAL health check
 *   -1  -- recv error, malformed header, unsupported protocol
 * --------------------------------------------------------------------------*/
int
trueip_parse_proxy_v1(SOCKET sock, struct in_addr *real_ip_out)
{
    char        line[TRUEIP_MAX_HEADER + 1]; /* header max + NUL terminator     */
    int         len = 0;
    char        ch;
    int         rc;

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
        if (avail < 6) {
            /* Fewer than 6 bytes in the buffer — cannot be a PROXY header.
             * 6 is the minimum to distinguish "PROXY " from telnet IAC or
             * a raw data connection. */
            return -1;
        }
    }

    /* -- Step 2: read byte-at-a-time until \r\n or max length -------------
     *
     * We stop at PROXY_HEADER_MAX (107) bytes per the PROXY Protocol v1 spec.
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

    /* -- Step 3: NUL-terminate (already done in the loop above) ----------- */

    /* -- Step 4: check the "PROXY " prefix (6 bytes) ---------------------- */
    if (strncmp(line, "PROXY ", 6) != 0) {
        /* The first 6 bytes are not "PROXY " — this is not a PROXY Protocol
         * connection.  Return 0 so the caller can decide based on require_header. */
        return 0;
    }

    /* -- Step 5: sscanf parse --------------------------------------------- */
    fields = sscanf(line, "PROXY %15s %63s %63s %d %d",
                    proto, src_ip, dst_ip, &src_port, &dst_port);

    /* -- Step 6: check protocol field ------------------------------------- */
    if (fields >= 1 && strncmp(proto, "LOCAL", 5) == 0) {
        /* PROXY LOCAL is an HAProxy health-check "connection".  The spec says
         * the receiver must ignore it and not perform IP substitution.
         * Return 0 so the caller knows no real-IP was extracted. */
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

    /* -- Step 7: strip "::ffff:" IPv4-mapped IPv6 prefix ------------------
     *
     * Node.js running on a dual-stack socket (and some other proxies) sends
     * the source IP as "::ffff:203.0.113.42" instead of "203.0.113.42".
     * The "::ffff:" prefix is 7 characters.  Advancing the pointer past it
     * leaves a standard dotted-decimal string for inet_addr(). */
    ip_ptr = src_ip;
    if (strncmp(ip_ptr, "::ffff:", 7) == 0) {
        ip_ptr += 7;
    }

    /* -- Step 8: convert dotted-decimal to binary network address --------- */
    addr = inet_addr(ip_ptr);
    if (addr == INADDR_NONE) {
        /* INADDR_NONE means inet_addr() could not parse the string.
         * This catches "255.255.255.255" as well, but that is an invalid
         * source address in a real connection, so rejecting it is correct. */
        return -1;
    }

    /* -- Step 9: store result and return success -------------------------- */
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
