/*
 * trueip_core.h -- PROXY Protocol v1 shared core: structs, constants, prototypes
 *
 * Purpose:
 *   Defines all types and function prototypes used by both the TRUEIP MBBS10
 *   module (trueip.c) and any future consumer (GALTCPIP integration, test
 *   harness, standalone proxy front-end).  Intentionally SDK-free so it can
 *   be included in projects that do not link the Worldgroup/MBBS10 SDK.
 *
 * Invariants:
 *   - NO Worldgroup/MBBS10 SDK types.  No galgsbl.h, no gsx.h, no sectypes.h.
 *   - Only raw Winsock 2 and Windows API types (SOCKET, in_addr, HANDLE, etc.).
 *   - All identifiers are prefixed trueip_ / TRUEIP_ to avoid collisions when
 *     this header is included alongside other modules in the same address space.
 *   - Consumers must link against ws2_32.lib and initialise Winsock 2 before
 *     calling any function declared here.
 *   - This header does NOT call WSAStartup / WSACleanup — that is the caller's
 *     responsibility.
 *
 * Dependencies:
 *   <winsock2.h>   — SOCKET, struct in_addr, ioctlsocket, recv, FIONREAD
 *   <windows.h>    — HANDLE, WORD, ULONGLONG, GetTickCount64, EVENTLOG_*
 *
 * Thread safety:
 *   trueip_check_rate() mutates a struct trueip_rate — callers must serialise
 *   access if the rate limiter is shared across threads.  All other functions
 *   are stateless and re-entrant.
 */

#ifndef TRUEIP_CORE_H
#define TRUEIP_CORE_H

/*
 * Winsock2 must come before windows.h to avoid the winsock.h / winsock2.h
 * inclusion conflict that produces hundreds of redefinition warnings under
 * the Microsoft compiler.
 */
#include <winsock2.h>
#include <windows.h>


/* ===========================================================================
 * Constants
 * ========================================================================= */

/*
 * TRUEIP_VERSION -- module version string, bumped on every public release.
 * Printed at startup and in Event Log entries so operators can confirm which
 * build is loaded without inspecting the DLL on disk.
 */
#define TRUEIP_VERSION      "1.0.0"

/*
 * TRUEIP_MAX_HEADER -- maximum byte length of a PROXY Protocol v1 header line.
 *
 * RFC/de-facto spec sizes:
 *   "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"  = 56 bytes
 *   "PROXY TCP6 <39-char addr> <39-char addr> 65535 65535\r\n"    = 108 bytes
 *
 * We reject TCP6 connections (IPv4-only mode), so 107 is a safe upper bound
 * that prevents runaway reads without wasting buffer space.  The parse loop
 * aborts with -1 if it reaches this limit before finding \r\n.
 */
#define TRUEIP_MAX_HEADER   107

/*
 * TRUEIP_MAX_TRUSTED -- maximum number of trusted proxy IP addresses.
 *
 * Eight slots covers every realistic single-datacenter or multi-region HA
 * setup without requiring heap allocation.  Kept small deliberately: a long
 * trusted list is usually a misconfiguration.
 */
#define TRUEIP_MAX_TRUSTED  8

/*
 * TRUEIP_TRUSTED_LEN -- maximum byte length (including NUL) of each trusted
 * IP string slot.  64 bytes comfortably holds dotted-decimal IPv4 (16 bytes)
 * with room for future CIDR notation or IPv6 literals if policy changes.
 */
#define TRUEIP_TRUSTED_LEN  64


/* ===========================================================================
 * Structs
 * ========================================================================= */

/*
 * struct trueip_config -- runtime configuration, populated from MCV at init.
 *
 * Callers zero-initialise this struct before passing it to
 * trueip_parse_trusted_ips() or any function that reads configuration fields.
 * Default values (port 2324, require_header=1, etc.) are applied by the
 * module init code, not here, so this header stays SDK-free.
 */
struct trueip_config {
    /* Listening port for proxy connections.  The module accepts incoming TCP
     * connections on this port and expects a PROXY v1 header before forwarding
     * to the game port.  Default: 2324. */
    int   proxy_port;

    /* 1 = reject connections that arrive without a valid PROXY header.
     * 0 = pass connections through with the socket's own source address when
     *     no header is present (useful for split-traffic setups where direct
     *     connections are also accepted on the same listener). */
    int   require_header;

    /* List of trusted proxy IP addresses in dotted-decimal form.
     * Only connections from these IPs will have their PROXY header honoured.
     * If trusted_ip_count == 0 the trust check is skipped (accept any source).
     * Populated by trueip_parse_trusted_ips() from the MCV TRUSTIP string. */
    char  trusted_ips[TRUEIP_MAX_TRUSTED][TRUEIP_TRUSTED_LEN];

    /* Number of valid entries in trusted_ips[].  0 means no filtering. */
    int   trusted_ip_count;

    /* Maximum new connections accepted per second across the entire module.
     * 0 = no rate limit.  Enforced via struct trueip_rate + GetTickCount64
     * rather than an OS-level token bucket so it works without elevated
     * privileges. */
    int   max_conn_per_sec;

    /* 1 = write verbose diagnostic entries to Windows Event Log.
     * 0 = only write warnings and errors.  Performance impact is negligible
     *     because Event Log calls are asynchronous, but operators often disable
     *     this on high-traffic systems to reduce log volume. */
    int   log_enabled;

    /* Maximum Event Log / file log size in kilobytes before rotation.
     * Evaluated only when log_enabled == 1. */
    int   max_log_kb;
};

/*
 * struct trueip_counters -- session-lifetime statistics, printed on shutdown.
 *
 * All fields start at zero and should be incremented via InterlockedIncrement
 * where multi-thread access is possible.  The struct itself is not padded for
 * any particular alignment — callers must not rely on field offsets across
 * compiler versions.
 */
struct trueip_counters {
    /* Total TCP connections accepted on the proxy port since module load. */
    unsigned long conn_total;

    /* Connections that supplied a valid PROXY header and were forwarded with
     * the real client IP injected. */
    unsigned long conn_proxied;

    /* Connections dropped because no PROXY header was present and
     * require_header == 1. */
    unsigned long conn_rejected_header;

    /* Connections dropped because the source IP was not in the trusted list. */
    unsigned long conn_rejected_ip;

    /* Connections dropped because the per-second rate limit was exceeded. */
    unsigned long conn_rate_limited;
};

/*
 * struct trueip_rate -- sliding window rate-limit state.
 *
 * Uses a fixed 1-second tumbling window keyed on GetTickCount64.  Not a
 * leaky bucket — the window resets hard at the start of each second.  This
 * is intentional: simpler, no drift, and bursty behaviour within one second
 * is acceptable for BBS connection rates.
 *
 * Callers must serialise access when the same struct is shared across threads.
 */
struct trueip_rate {
    /* GetTickCount64 value at the start of the current 1-second window.
     * Reset whenever the elapsed time since window_start exceeds 1000 ms. */
    ULONGLONG window_start;

    /* Number of connections accepted in the current window.
     * Compared against trueip_config.max_conn_per_sec. */
    int       window_count;
};


/* ===========================================================================
 * Function prototypes
 * ========================================================================= */

/*
 * trueip_parse_proxy_v1 -- read and parse a PROXY Protocol v1 header.
 *
 * Design decisions:
 *   - Uses ioctlsocket(FIONREAD) as a preflight check before reading.  This
 *     avoids blocking on a socket that has no data yet, which would stall the
 *     caller's thread.  It does NOT call recvbw (the Worldgroup buffered-recv
 *     helper) because this header must remain SDK-free and because recvbw
 *     manages its own buffer state that would corrupt the stream if called
 *     before the PROXY header is fully consumed.
 *   - Reads one byte at a time (recv with len=1) up to TRUEIP_MAX_HEADER bytes
 *     until \r\n is found.  Single-byte reads are slightly slower but
 *     eliminate the need for a secondary buffer or ungetting bytes — the
 *     remaining stream bytes stay in the kernel socket buffer, intact, ready
 *     for the next recv call (e.g., the game's normal input handler).
 *   - Strips the "::ffff:" IPv4-mapped IPv6 prefix so that proxies that emit
 *     TCP4-over-TCP6 addresses ("::ffff:1.2.3.4") produce a clean in_addr.
 *   - "PROXY LOCAL" health-check lines are treated as "no real client IP"
 *     (return 0) rather than an error, so load-balancer keepalives do not
 *     fill the event log with warnings.
 *   - TCP6 addresses are rejected with return -1.  The module is IPv4-only.
 *
 * Parameters:
 *   sock         -- connected client socket (must be valid and readable)
 *   real_ip_out  -- on success (return 1), populated with the client's real
 *                   IPv4 address as extracted from the PROXY header.
 *                   Untouched on return 0 or -1.
 *
 * Returns:
 *    1  header parsed successfully; *real_ip_out contains the client IP
 *    0  no PROXY header present, or "PROXY LOCAL" health check; caller should
 *       use the socket's own source address and proceed normally
 *   -1  malformed header, unsupported family (TCP6), or recv error; caller
 *       should close the socket and increment conn_rejected_header
 *
 * Side effects:
 *   - Consumes exactly the PROXY header bytes from the socket receive buffer.
 *   - Does NOT modify the socket's blocking mode.
 *   - Does NOT close the socket on error — caller decides whether to close.
 */
int trueip_parse_proxy_v1(SOCKET sock, struct in_addr *real_ip_out);

/*
 * trueip_check_trusted -- verify that a source IP is authorised to supply
 * PROXY headers.
 *
 * Why this check exists:
 *   Without it, any client can forge "PROXY TCP4 1.2.3.4 ..." and inject an
 *   arbitrary source address.  Only traffic from known proxy servers should
 *   be trusted to supply a real client IP.
 *
 * Parameters:
 *   source  -- IPv4 address of the connecting peer (from getpeername or
 *              equivalent, obtained BEFORE the PROXY header is parsed)
 *   cfg     -- module configuration; trusted_ips[] and trusted_ip_count are
 *              read but not mutated
 *
 * Returns:
 *   1  source IP is trusted (or trusted_ip_count == 0, i.e., no filtering)
 *   0  source IP is not in the trusted list; caller should close the socket
 *      and increment conn_rejected_ip
 */
int trueip_check_trusted(struct in_addr source, const struct trueip_config *cfg);

/*
 * trueip_check_rate -- enforce the per-second connection rate limit.
 *
 * Updates the sliding window in *rate and decides whether to admit or reject
 * the current connection.  Must be called once per incoming connection,
 * BEFORE accepting it into the game.
 *
 * Window semantics:
 *   Each call compares GetTickCount64() to rate->window_start.  If more than
 *   1000 ms have elapsed, the window resets (window_start = now, window_count
 *   = 1) and the connection is admitted.  Within the window, window_count is
 *   incremented and compared to max_per_sec.
 *
 * Parameters:
 *   rate        -- rate-limit state; mutated on every call (window_start and
 *                  window_count updated).  Caller must serialise if shared.
 *   max_per_sec -- limit from trueip_config.max_conn_per_sec.  Pass 0 to
 *                  disable rate limiting entirely (function always returns 1).
 *
 * Returns:
 *   1  connection admitted (within limit or no limit configured)
 *   0  connection rejected (would exceed max_per_sec in current window);
 *      caller should close the socket and increment conn_rate_limited
 */
int trueip_check_rate(struct trueip_rate *rate, int max_per_sec);

/*
 * trueip_parse_trusted_ips -- parse a comma-separated IP list into cfg.
 *
 * Splits the string on commas, trims leading and trailing ASCII whitespace
 * from each token, and stores up to TRUEIP_MAX_TRUSTED entries in
 * cfg->trusted_ips[].  Sets cfg->trusted_ip_count to the number of entries
 * stored.  Silently discards tokens that exceed TRUEIP_TRUSTED_LEN - 1 bytes
 * or that would exceed TRUEIP_MAX_TRUSTED; the caller should log a warning
 * if the source string is sysop-supplied.
 *
 * Parameters:
 *   csv  -- NUL-terminated comma-separated IP string, e.g.
 *           "192.168.1.1, 10.0.0.2".  May be NULL or empty string; in that
 *           case trusted_ip_count is set to 0 (no filtering).
 *   cfg  -- target config struct; trusted_ips[][] and trusted_ip_count are
 *           written.  All other fields are untouched.
 *
 * Returns: void (errors handled silently per above).
 */
void trueip_parse_trusted_ips(const char *csv, struct trueip_config *cfg);

/*
 * trueip_log_event -- write a formatted message to the Windows Event Log.
 *
 * Why Windows Event Log instead of a file:
 *   Event Log is always available, requires no file-path configuration, and
 *   is readable remotely via Event Viewer.  A supplementary file log can be
 *   layered on top, but the Event Log is the baseline that is always on.
 *
 * Parameters:
 *   hLog  -- event source handle from RegisterEventSource().  The caller is
 *            responsible for RegisterEventSource / DeregisterEventSource
 *            lifecycle.  If hLog is NULL, the call is a no-op (safe to call
 *            before the log handle is initialised).
 *   type  -- severity: EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
 *            or EVENTLOG_ERROR_TYPE (defined in <windows.h>)
 *   fmt   -- printf-style format string.  Resulting message must be < 4096
 *            characters; longer messages are silently truncated.
 *   ...   -- variadic arguments matching fmt
 *
 * Returns: void.  Failures (e.g. Event Log service not running) are silently
 *          swallowed — logging must never crash the BBS.
 */
void trueip_log_event(HANDLE hLog, WORD type, const char *fmt, ...);

/*
 * trueip_format_ip -- format an IPv4 address into a caller-supplied buffer.
 *
 * Why NOT inet_ntoa:
 *   inet_ntoa() returns a pointer to a static internal buffer that is
 *   overwritten on every call.  It is therefore unsafe when two addresses
 *   must both be live in the same expression or in adjacent printf arguments,
 *   a common pattern in connection-logging code such as:
 *       printf("proxy=%s real=%s", inet_ntoa(proxy), inet_ntoa(real));
 *   This function expands each octet from the in_addr byte fields directly
 *   into the caller-supplied buf[], which is independent per call and
 *   safe to use multiple times in the same statement.
 *
 * Parameters:
 *   addr     -- IPv4 address to format (network byte order, as stored in
 *               struct in_addr)
 *   buf      -- output buffer; must be at least 16 bytes ("255.255.255.255\0")
 *   bufsize  -- size of buf in bytes; output is silently truncated to
 *               bufsize - 1 with a NUL terminator if bufsize < 16
 *
 * Returns: void.
 */
void trueip_format_ip(struct in_addr addr, char *buf, int bufsize);


#endif /* TRUEIP_CORE_H */
