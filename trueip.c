/******************************************************************************
 * trueip.c — PROXY Protocol v1 Module for MBBS10
 *
 * PURPOSE:
 *   When MBBS10 sits behind a reverse proxy (HAProxy, nginx, BBSFirewall),
 *   every incoming connection appears to originate from the proxy's IP. This
 *   module corrects that by reading the PROXY Protocol v1 header that the
 *   reverse proxy prepends, extracting the real client IP, and writing it
 *   into tcpipinf[usrnum].inaddr — the single source of truth that every
 *   existing IP consumer on the BBS reads (LANCE, WHO, audit trail, findtvar).
 *
 * HOW IT WORKS:
 *   1. TRUEIP registers a TCP listener on a dedicated proxy port (default 2324)
 *      via regtcpsvr().  Configure your reverse proxy to forward to this port.
 *   2. When a connection arrives, trueip_incall() fires on the BBS scheduler
 *      thread (single-threaded — no synchronization needed).
 *   3. The PROXY Protocol v1 header is read byte-at-a-time from the raw socket
 *      BEFORE handing the socket to the telnet daemon.
 *   4. tntincall() is called — it creates a full BBS telnet session and sets
 *      usrnum.  After it returns, we overwrite tcpipinf[usrnum].inaddr with
 *      the real IP.  SOCKET IS THEN OWNED BY GALTNTD — never close it.
 *
 * KEY INVARIANTS:
 *   - winsock2.h MUST be included before any SDK header (avoids redefinitions)
 *   - All callbacks are __cdecl (BBS scheduler calling convention)
 *   - clsskt() instead of closesocket() for all SDK-managed sockets — clsskt
 *     removes the socket from GALTCPIP's event notification table; raw
 *     closesocket() leaves a dangling entry
 *   - Never call clsskt() after tntincall() succeeds — the socket is GALTNTD's
 *   - Never block in incall — the BBS scheduler is single-threaded
 *   - _snprintf(detail, 128, ...) for audit trail — AUDDETSIZ = 128
 *   - %u.%u.%u.%u byte-expansion for IP logging (inet_ntoa uses a static
 *     buffer that gets clobbered by multiple calls in one log statement)
 *
 * KEY DEPENDENCIES:
 *   GALTCPIP.DLL — tcpipinf[], clskt, claddr, regtcpsvr, clsskt, recvbw
 *   GALTNTD.DLL  — tntincall
 *   WGSERVER.EXE — usrnum, nterms, shocst, hAuditTrail (ordinal/IAT);
 *                  register_module, gmdnam, prf, margv, stzcpy, rstmbk,
 *                  setmbk, clsmsg, outprf (resolved via GetProcAddress —
 *                  see WHY block in init__trueip Step 1 for the reason)
 *   WS2_32.LIB   — recv, inet_addr
 *
 * VERSION: 1.0.0
 * AUTHOR:  Realmforge
 *****************************************************************************/

/*
 * WHY winsock2.h MUST be first:
 *   The SDK's TCPIP.H includes <windows.h> (indirectly via the GCWINNT path)
 *   which pulls in winsock.h.  If winsock2.h is included AFTER windows.h,
 *   both winsock.h and winsock2.h are in scope simultaneously → hundreds of
 *   redefinition errors.  Including winsock2.h first prevents windows.h from
 *   including winsock.h (it checks _WINSOCKAPI_ / _WINSOCK2API_ guard macros).
 */
#include <winsock2.h>       /* MUST be before windows.h and all SDK headers */
#include <windows.h>        /* HANDLE, DWORD, GetTickCount64, Event Log APIs */
#include "gcomm.h"          /* Core Galacticomm types: INT, CHAR, GBOOL, etc. */
#include "majorbbs.h"       /* usrnum, nterms, shocst, register_module, margv */
#include "MCVAPI.H"         /* opnmsg, clsmsg, setmbk, rstmbk, ynopt, numopt, stgopt */
#include "TCPIP.H"          /* tcpipinf[], clskt, claddr, regtcpsvr, clsskt, recvbw */
/* TELNETD.H cannot compile standalone — its TNTDEXP macro and struct tnoscb
 * are defined in internal headers we don't have.  We declare tntincall manually,
 * matching the pattern used by federation_recon_mod.c. */
__declspec(dllimport) void tntincall(int gotchn);
/* AUDAPI.h pulled in audfAddEntry/hAuditTrail which aren't in WGSERVER_LIB.LIB.
 * Resolve at runtime via GetProcAddress so the module links without them. */
#define AUDDETSIZ 128
typedef int (__cdecl *pfn_audfAddEntry)(void*, const char*, const char*, ...);
typedef void (__cdecl *pfn_globalcmd)(int (__cdecl *)(void));
static pfn_audfAddEntry  g_pfn_audfAddEntry = NULL;
static pfn_globalcmd     g_pfn_globalcmd    = NULL;
static void             *g_hAuditTrail      = NULL;

/* WHY GetProcAddress for these 9 symbols:
 *   WGSERVER.EXE exports them with a leading underscore (e.g. "_register_module")
 *   as required by the x86 __cdecl calling convention for C names.  The SDK import
 *   library WGSERVER_LIB.LIB strips the underscore in its stub, so the linker
 *   resolves the import as "register_module" — but the real export is
 *   "_register_module".  Result: ERROR_PROC_NOT_FOUND (0x7F) at load time.
 *
 *   Functions imported by ORDINAL (usrnum, nterms, shocst, sameas, ...) are
 *   unaffected because ordinal resolution bypasses name matching entirely.
 *
 *   The fix: never reference these 9 symbols via the import library.  Instead,
 *   resolve them at runtime using GetProcAddress("_<name>") against the already-
 *   loaded WGSERVER.EXE module handle.  GetProcAddress uses the raw export
 *   directory name — the leading underscore is correct and required here. */

/* Function pointer typedefs — all __cdecl to match the x86 BBS calling convention.
 *
 * Type notes:
 *   pfn_setmbk: MCVAPI.H declares setmbk(HMCVFILE mb) — HMCVFILE is struct msgblk*.
 *               We use void* to avoid pulling in the full MCVAPI struct definition
 *               here.  The pointer size is identical on x86-32 (4 bytes), so the
 *               call is ABI-compatible.
 *   pfn_clsmsg: MCVAPI.H declares clsmsg(HMCVFILE mbptr) — same reasoning.
 *   pfn_register_module: returns INT (the module's state code), takes struct module*.
 *               We use void* for the parameter for the same forward-declaration reason. */
typedef int    (__cdecl *pfn_register_module)(void*);
typedef char * (__cdecl *pfn_gmdnam)(const char*);
typedef void   (__cdecl *pfn_prf)(const char*, ...);
typedef void   (__cdecl *pfn_stzcpy)(char*, const char*, int);
typedef void   (__cdecl *pfn_rstmbk)(void);
typedef void   (__cdecl *pfn_setmbk)(void*);   /* arg is HMCVFILE (struct msgblk*) */
typedef void   (__cdecl *pfn_clsmsg)(void*);   /* arg is HMCVFILE (struct msgblk*) */
typedef void   (__cdecl *pfn_outprf)(int);
typedef char * (__cdecl *pfn_getMsgBlk)(int);

/* Static function pointer storage — initialised to NULL, filled in init__trueip
 * during the GetProcAddress block (Step 1b).  Every call site checks for NULL
 * before invoking, so a missing export is a clean no-op rather than a crash. */
static pfn_register_module g_pfn_register_module = NULL;
static pfn_gmdnam          g_pfn_gmdnam          = NULL;
static pfn_prf             g_pfn_prf             = NULL;
static pfn_stzcpy          g_pfn_stzcpy          = NULL;
static pfn_rstmbk          g_pfn_rstmbk          = NULL;
static pfn_setmbk          g_pfn_setmbk          = NULL;
static pfn_clsmsg          g_pfn_clsmsg          = NULL;
static pfn_outprf          g_pfn_outprf          = NULL;
static pfn_getMsgBlk       g_pfn_getMsgBlk       = NULL;

/* margv is a DATA global (char**), not a function.
 * MAJORBBS.H declares it as WGSEXPV(CHAR*) margv[INPSIZ/2] — an array of char*
 * pointers.  We resolve the array base address via GetProcAddress and store it
 * as a char** so call sites can index it as g_pmargv[0], g_pmargv[1], etc. */
static char              **g_pmargv              = NULL;

#include "trueip.h"         /* TRUEIP_TPORT, TRUEIP_REQHDR, etc. (msg number #defines) */
#include <stdio.h>          /* _snprintf, fopen, fprintf, fclose */
#include <string.h>         /* strncmp, sscanf, memset */

/* TRUEIP_VERSION is defined in trueip.h — do not redefine here. */

/* Maximum PROXY Protocol v1 header length per spec.
 * "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n" = 56 bytes.
 * We allow 107 to match the spec's maximum (including TCP6 addresses). */
#define PROXY_HEADER_MAX    107

/* PROXY Protocol v2 — 12-byte binary magic signature.
 * The spec defines this exact byte sequence; any other first byte rules out v2. */
static const unsigned char PROXY_V2_MAGIC[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

/* Maximum addr_len we will accept from a v2 header.
 * The spec allows up to 65535 bytes of TLV extensions — pathological in practice.
 * Real-world TLVs (PP2_TYPE_SSL, PP2_TYPE_AUTHORITY) are tens of bytes.
 * Cap at 512 to prevent a malicious header from stalling the consume loop. */
#define PROXY_V2_ADDR_LEN_CAP  512

/* Maximum number of trusted proxy IPs we'll parse from the config string.
 * A BBS operator rarely has more than a handful of upstream proxies. */
#define TRUSTED_IP_MAX      8

/* Rate-limit sliding window duration in milliseconds. */
#define RATE_WINDOW_MS      1000

/* ============================================================================
 * Forward declarations — all callbacks must appear before struct module.
 * The BBS SDK dispatches these by function pointer; __cdecl is mandatory to
 * match the scheduler's calling convention.
 * ============================================================================*/
static VOID         trueip_shutdown(VOID);
static VOID __cdecl trueip_incall(INT gotchn);
static INT  __cdecl trueip_global_handler(VOID);

/* ============================================================================
 * Module interface block.
 * TRUEIP is a pure background module — users never "enter" it from the menu.
 * Only finrou (trueip_shutdown) is wired; everything else is NULL.
 * The descrp field is filled by init__trueip() from the MDF via gmdnam().
 * ============================================================================*/
struct module TRUEIP = {
    "",             /* descrp  — filled from TRUEIP.MDF by gmdnam() at init  */
    NULL,           /* lonrou  — no logon supplemental (background module)    */
    NULL,           /* sttrou  — users never enter TRUEIP via the menu        */
    NULL,           /* stsrou  — no status-input handler                      */
    NULL,           /* injrou  — no injoth handler                            */
    NULL,           /* lofrou  — no logoff supplemental                       */
    NULL,           /* huprou  — no hangup handler                            */
    NULL,           /* mcurou  — no midnight-cleanup handler                  */
    NULL,           /* dlarou  — no delete-account handler (no user data)     */
    trueip_shutdown /* finrou  — called at BBS shutdown: log counters, cleanup*/
};

/* register_module() return value — stored even though nobody enters TRUEIP.
 * The BBS requires every module to call register_module() and store the result
 * so the module appears in the module table for LANCE/WGSETUP inspection. */
INT usrstt_trueip;

/* ============================================================================
 * Configuration — read from TRUEIP.MCV at init via opnmsg/ynopt/numopt/stgopt.
 * Sysop edits these through WGSCNF; we read them once at startup.
 * ============================================================================*/

/* MCV handle — opened in init__trueip(), closed in trueip_shutdown(). */
static HMCVFILE g_mcv                  = NULL;

/* TCP port the PROXY-protocol listener binds to (default 2324).
 * Must NOT be 23 (stock telnet port — already owned by GALTNTD). */
static INT      g_proxy_port           = 2324;

/* TRUE = reject connections that arrive without a valid PROXY header.
 * FALSE = fall through to tntincall without IP substitution (allows direct
 * connections for debugging, not recommended in production). */
static GBOOL    g_require_header       = TRUE;

/* Raw comma-separated trusted-IP config string (stgopt-allocated). */
static CHAR    *g_trusted_ip_str       = NULL;

/* Parsed trusted proxy IP addresses (up to TRUSTED_IP_MAX entries).
 * If g_trusted_ip_count == 0, any source IP is accepted — less secure, but
 * useful when the proxy IP is dynamic (e.g. Docker, cloud NAT). */
static CHAR     g_trusted_ips[TRUSTED_IP_MAX][64];
static INT      g_trusted_ip_count     = 0;

/* Max new connections per second on the proxy port.  0 = no limit.
 * Protects the single-threaded scheduler from connection floods. */
static INT      g_max_conn_per_sec     = 10;

/* Enable per-connection debug logging to TRUEIP.LOG.
 * Disable in production; Windows Event Log is the operational channel. */
static GBOOL    g_log_enabled          = FALSE;

/* Log rotation threshold in KB.  When TRUEIP.LOG exceeds this, it is renamed
 * to TRUEIP.BAK and a fresh log is started.  0 = no rotation. */
static INT      g_max_log_kb           = 1024;

/* Set to 1 if regtcpsvr() succeeded — used by TRUEIP STATUS display. */
static INT      g_server_ok            = 0;

/* ============================================================================
 * Runtime counters — session-lifetime, printed on shutdown and STATUS command.
 * All are 32-bit; realistic BBS uptime makes 32-bit overflow impossible.
 * ============================================================================*/
static ULONG    g_conn_total           = 0;   /* all incall() invocations     */
static ULONG    g_conn_proxied         = 0;   /* successful IP substitutions  */
static ULONG    g_conn_rejected_header = 0;   /* no/bad PROXY header          */
static ULONG    g_conn_rejected_ip     = 0;   /* source not in trusted list   */
static ULONG    g_conn_rate_limited    = 0;   /* hit per-second rate cap      */

/* ============================================================================
 * Rate limiting — sliding 1-second window via GetTickCount64.
 * GetTickCount64 is monotonic and wraps only after ~585 million years.
 * We track the count of connections accepted in the current 1-second bucket.
 * ============================================================================*/
static ULONGLONG g_rate_window_start   = 0;
static INT       g_rate_window_count   = 0;

/* ============================================================================
 * Windows Event Log handle — RegisterEventSource() in init, DeregisterEvent-
 * Source() in shutdown.  Used for operational events (start/stop, warnings,
 * errors) that administrators need in SCOM / Splunk / Event Viewer.
 * ============================================================================*/
static HANDLE   g_hEventLog            = NULL;

/* ============================================================================
 * Logging helpers.
 *
 * Two channels:
 *   1. Windows Event Log — always available, operational-grade, for admins.
 *   2. TRUEIP.LOG       — detailed per-connection trace, disabled by default.
 *
 * WHY NOT prf/outprf for logging:
 *   prf() writes to the *current user's* output buffer (controlled by usrnum).
 *   In trueip_incall(), no BBS session exists yet — there is no current user.
 *   Calling prf() here would corrupt a random user's output buffer.
 *   CRT fopen/fprintf are the correct primitive for module-level file logging.
 * ============================================================================*/

/* WHY a helper instead of inline ReportEvent:
 *   ReportEvent requires a LPCSTR* array; wrapping it prevents boilerplate
 *   repetition at every call site and keeps call sites readable. */
static VOID
trueip_event_log(WORD type, const CHAR *msg)
{
    /* ReportEvent expects an array of LPCSTR pointers, not a direct string. */
    LPCSTR strings[1];
    strings[0] = msg;
    if (g_hEventLog != NULL) {
        ReportEventA(
            g_hEventLog,    /* source handle from RegisterEventSource        */
            type,           /* EVENTLOG_INFORMATION_TYPE / WARNING / ERROR   */
            0,              /* category (0 = none)                           */
            0,              /* event ID (0 = generic — no .mc message file)  */
            NULL,           /* user security identifier (not needed)         */
            1,              /* number of strings in 'strings' array          */
            0,              /* binary data size (none)                       */
            strings,        /* array of message strings                      */
            NULL            /* binary data pointer (none)                    */
        );
    }
}

/* WHY a vararg log macro instead of a function:
 *   Avoids a double-vsnprintf call.  The macro builds the message into a
 *   stack buffer once and passes it to both file and event log sinks. */
static VOID
trueip_log_impl(const CHAR *fmt, ...)
{
    CHAR buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    buf[sizeof(buf) - 1] = '\0';
    va_end(ap);

    /* Windows Event Log — every log call goes here (even if file logging is
     * off).  This is the operational channel for admins. */
    trueip_event_log(EVENTLOG_INFORMATION_TYPE, buf);

    /* File log — only if enabled in config.  Disabled by default.
     * We open, write, and close on each call intentionally: this is a debug
     * channel, not a hot path.  It keeps the code simple and ensures no data
     * is lost if the BBS crashes mid-session. */
    if (g_log_enabled) {
        FILE *fp = fopen("TRUEIP.LOG", "a");
        if (fp != NULL) {

            /* Log rotation: if the file exceeds the configured KB threshold,
             * rename it to .BAK and start fresh.  ftell() gives us the current
             * position (= file size since we're at end after "a" open). */
            if (g_max_log_kb > 0) {
                long pos = ftell(fp);
                if (pos > (long)(g_max_log_kb * 1024)) {
                    fclose(fp);
                    /* DeleteFileA ignores errors — if .BAK is locked, we lose
                     * the old backup.  That's acceptable for a debug log. */
                    DeleteFileA("TRUEIP.BAK");
                    MoveFileA("TRUEIP.LOG", "TRUEIP.BAK");
                    fp = fopen("TRUEIP.LOG", "a");
                    if (fp == NULL) return;
                }
            }

            fprintf(fp, "%s\r\n", buf);
            fclose(fp);
        }
    }
}

/* Convenience macro so call sites don't need the _impl suffix. */
#define trueip_log(fmt, ...) trueip_log_impl(fmt, ##__VA_ARGS__)

/* ============================================================================
 * parse_trusted_ips() — parse the comma-separated trusted-IP config string
 * into g_trusted_ips[].
 *
 * WHY comma-separated strings instead of multiple config entries:
 *   WGSCNF config options are one-per-entry.  Storing multiple IPs as a
 *   single delimited string in one stgopt entry is the standard MBBS10
 *   convention (e.g. GALTCPIP's hostdeny file path string).
 * ============================================================================*/
static VOID
parse_trusted_ips(const CHAR *str)
{
    const CHAR *p = str;
    INT         i = 0;

    g_trusted_ip_count = 0;

    if (str == NULL || str[0] == '\0') {
        /* Empty string = accept from any source.
         * Log a warning — production deployments should lock this down. */
        trueip_log("TRUEIP: trusted IP list empty — accepting connections from any source (set TRUSTIP in WGSCNF for production)");
        return;
    }

    while (*p != '\0' && i < TRUSTED_IP_MAX) {
        CHAR entry[64];
        INT  j = 0;

        /* Skip leading whitespace and commas. */
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (*p == '\0') break;

        /* Copy until comma or end. */
        while (*p != '\0' && *p != ',' && j < (INT)sizeof(entry) - 1) {
            entry[j++] = *p++;
        }
        entry[j] = '\0';

        /* Trim trailing whitespace. */
        while (j > 0 && (entry[j-1] == ' ' || entry[j-1] == '\t')) {
            entry[--j] = '\0';
        }

        if (j > 0) {
            /* Validate that it's a parseable IPv4 address before storing.
             * inet_addr returns INADDR_NONE (0xFFFFFFFF) on parse failure. */
            if (inet_addr(entry) == INADDR_NONE) {
                trueip_log("TRUEIP: WARNING — invalid trusted IP '%s' in config; skipped", entry);
            } else {
                strncpy(g_trusted_ips[i], entry, sizeof(g_trusted_ips[i]) - 1);
                g_trusted_ips[i][sizeof(g_trusted_ips[i]) - 1] = '\0';
                i++;
            }
        }
    }

    g_trusted_ip_count = i;
    trueip_log("TRUEIP: %d trusted proxy IP(s) loaded", g_trusted_ip_count);
}

/* ============================================================================
 * is_trusted_source() — check whether the connecting IP is in the trusted list.
 *
 * Called from trueip_incall() before reading the PROXY header.  If the source
 * is not trusted, we close the socket immediately — an untrusted source could
 * send a forged PROXY header claiming any IP.
 *
 * Returns: TRUE if trusted (or if the trusted list is empty), FALSE otherwise.
 * ============================================================================*/
static GBOOL
is_trusted_source(ULONG peer_ip)
{
    INT i;

    /* Empty trusted list = accept from any source. */
    if (g_trusted_ip_count == 0) {
        return TRUE;
    }

    for (i = 0; i < g_trusted_ip_count; i++) {
        /* Compare raw 32-bit addresses.  Both are in network byte order. */
        if (inet_addr(g_trusted_ips[i]) == peer_ip) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================================================================
 * check_rate_limit() — sliding 1-second window rate limiter.
 *
 * WHY rate limiting in incall:
 *   The BBS scheduler is single-threaded.  A connection flood arriving on the
 *   proxy port can starve all other scheduler work (user input, ticks).  The
 *   rate limiter is a lightweight first line of defense that costs one
 *   GetTickCount64() call per incall — essentially free.
 *
 * Returns: TRUE if the connection should be accepted, FALSE if rate-limited.
 * ============================================================================*/
static GBOOL
check_rate_limit(VOID)
{
    ULONGLONG now;

    /* 0 = no limit configured. */
    if (g_max_conn_per_sec <= 0) {
        return TRUE;
    }

    now = GetTickCount64();

    /* Start a new window if the current one has expired. */
    if (now - g_rate_window_start >= (ULONGLONG)RATE_WINDOW_MS) {
        g_rate_window_start = now;
        g_rate_window_count = 0;
    }

    g_rate_window_count++;

    if (g_rate_window_count > g_max_conn_per_sec) {
        return FALSE;
    }
    return TRUE;
}

/* ============================================================================
 * parse_proxy_v2_payload() — parse a PROXY Protocol v2 binary header.
 *
 * Called by parse_proxy_header() after it has confirmed the first 12 bytes
 * match PROXY_V2_MAGIC.  The full header has already been peek-buffered by
 * the caller; this function reads fields from peeked[], then consumes the
 * header bytes from the socket via recv() so tntincall gets a clean stream.
 *
 * PROXY v2 header layout (all multi-byte fields in network byte order):
 *   Bytes  0-11  magic (already verified by caller)
 *   Byte   12    upper nibble = version (must be 0x2)
 *                lower nibble = command (0x0=LOCAL health-check, 0x1=PROXY)
 *   Byte   13    upper nibble = family (0x1=AF_INET, 0x2=AF_INET6)
 *                lower nibble = transport (0x1=TCP)
 *   Bytes 14-15  addr_len (uint16, network byte order) — length of the
 *                address block that follows byte 15.  For TCP4: 12 bytes
 *                (src_addr+dst_addr+src_port+dst_port).  May be larger if
 *                TLV extensions (PP2_TYPE_SSL, etc.) are appended.
 *   Bytes 16+    address block:
 *                  TCP4: src_addr[4] dst_addr[4] src_port[2] dst_port[2]
 *                  TCP6: src_addr[16] dst_addr[16] src_port[2] dst_port[2]
 *
 * Total header = 16 + addr_len (28 bytes for a plain TCP4 header).
 *
 * PARAMETERS:
 *   skt       — raw socket (clskt at incall time); used only for consume recv
 *   peeked    — bytes returned by MSG_PEEK in the caller; must be >= 16 bytes
 *   peek_len  — number of valid bytes in peeked[]
 *   out_ip    — receives src_addr on success
 *
 * RETURNS:
 *    1 = success, *out_ip filled with real client IP
 *    0 = LOCAL command (health check) — no IP substitution
 *   -1 = error (unknown command, unsupported family, incomplete header,
 *               consume failed)
 *
 * ALL error and success paths log via trueip_log with a "v2" prefix so they
 * are distinguishable from v1 log lines in TRUEIP.LOG / Event Log.
 * ============================================================================*/
static INT
parse_proxy_v2_payload(INT skt, const char *peeked, INT peek_len, struct in_addr *out_ip)
{
    unsigned char   ver_cmd;    /* byte 12: version + command nibbles            */
    unsigned char   fam_trn;    /* byte 13: family + transport nibbles           */
    unsigned char   version;    /* upper nibble of byte 12 — must be 0x2        */
    unsigned char   command;    /* lower nibble of byte 12 — LOCAL=0, PROXY=1   */
    unsigned char   family;     /* upper nibble of byte 13 — AF_INET=1, INET6=2 */
    unsigned char   transport;  /* lower nibble of byte 13 — TCP=1              */
    unsigned short  addr_len_net; /* bytes 14-15 in network byte order          */
    INT             addr_len;   /* addr_len converted to host byte order        */
    INT             total;      /* full header size = 16 + addr_len             */
    CHAR            discard[256]; /* stack consume buffer — never heap           */
    INT             n;

    /* Caller guarantees peek_len >= 12 (v2 magic matched).
     * We need at least 16 bytes to read the full fixed header. */
    if (peek_len < 16) {
        trueip_log("TRUEIP v2: peek_len=%d < 16 — cannot read fixed header fields", peek_len);
        return -1;
    }

    /* -- Byte 12: version (upper nibble) + command (lower nibble) --------- */
    ver_cmd   = (unsigned char)peeked[12];
    version   = (ver_cmd >> 4) & 0x0F;
    command   = ver_cmd & 0x0F;

    if (version != 0x2) {
        trueip_log("TRUEIP v2: version nibble 0x%X != 0x2 — rejected", (unsigned)version);
        return -1;
    }

    /* LOCAL (0x0): HAProxy health check.  Spec says consume the header and
     * close or pass the connection.  We consume, then return 0 so the caller
     * applies the g_require_header policy (typically: reject the connection). */
    if (command == 0x0) {
        /* We still need addr_len to know how many bytes to consume.
         * Read bytes 14-15 via memcpy to avoid strict-aliasing UB. */
        memcpy(&addr_len_net, peeked + 14, 2);
        addr_len = (INT)ntohs(addr_len_net);
        total    = 16 + addr_len;

        trueip_log("TRUEIP v2: LOCAL command (health check) — consuming %d header bytes", total);

        /* Consume in 256-byte chunks so we don't need a large stack buffer. */
        while (total > 0) {
            INT chunk = (total < (INT)sizeof(discard)) ? total : (INT)sizeof(discard);
            n = recv(skt, discard, chunk, 0);
            if (n <= 0) {
                trueip_log("TRUEIP v2: LOCAL consume recv returned %d — connection broken", n);
                return -1;
            }
            total -= n;
        }
        return 0;  /* health check — caller will apply require_header policy */
    }

    if (command != 0x1) {
        trueip_log("TRUEIP v2: unknown command nibble 0x%X (expected 0x0=LOCAL or 0x1=PROXY)", (unsigned)command);
        return -1;
    }

    /* -- Byte 13: family (upper nibble) + transport (lower nibble) -------- */
    fam_trn   = (unsigned char)peeked[13];
    family    = (fam_trn >> 4) & 0x0F;
    transport = fam_trn & 0x0F;

    /* Only TCP over IPv4 is supported.  IPv6 requires struct in6_addr and
     * GALTCPIP's tcpipinf.inaddr is struct in_addr (32-bit only). */
    if (family == 0x2) {
        trueip_log("TRUEIP v2: TCP6 (AF_INET6) is not supported — rejected (tcpipinf.inaddr is 32-bit)");
        return -1;
    }

    if (family != 0x1 || transport != 0x1) {
        trueip_log("TRUEIP v2: unsupported family/transport (byte13=0x%02X) — only AF_INET/TCP (0x11) supported",
                   (unsigned)fam_trn);
        return -1;
    }

    /* -- Bytes 14-15: addr_len -------------------------------------------- */
    /* WHY memcpy instead of *(unsigned short*)(peeked+14):
     *   That cast is a strict-aliasing violation (reading char* memory as
     *   unsigned short*).  Benign on MSVC/x86 in practice but undefined per
     *   the C standard.  memcpy is equally fast after optimization and is
     *   portable. */
    memcpy(&addr_len_net, peeked + 14, 2);
    addr_len = (INT)ntohs(addr_len_net);

    /* Minimum addr_len for TCP4 is 12 bytes.  Not == 12 because TLV extensions
     * make it larger while still being a valid TCP4 header. */
    if (addr_len < 12) {
        trueip_log("TRUEIP v2: addr_len=%d < 12 — malformed TCP4 address block", addr_len);
        return -1;
    }

    /* Cap at 512 bytes.  The spec allows up to 65535 bytes of TLV extensions
     * but real-world TLVs are tens of bytes.  A value > 512 indicates either
     * a pathological extension or a malformed/malicious header. */
    if (addr_len > PROXY_V2_ADDR_LEN_CAP) {
        trueip_log("TRUEIP v2: addr_len=%d exceeds cap %d — rejected", addr_len, PROXY_V2_ADDR_LEN_CAP);
        return -1;
    }

    /* -- Completeness check -----------------------------------------------
     * We need at least 16 + addr_len peeked bytes to safely read src_addr.
     * If TLV extensions push the header beyond what was peeked, return -1
     * immediately.  No second retry loop — a real proxy sends the full header
     * in one TCP segment on LAN.  Doubling the scheduler stall window is worse
     * than rejecting the connection. */
    total = 16 + addr_len;
    if (peek_len < total) {
        trueip_log("TRUEIP v2: header incomplete (have %d peeked, need %d) — rejected", peek_len, total);
        return -1;
    }

    /* -- Extract src_addr (bytes 16-19) -----------------------------------
     * The address block starts at byte 16.  For TCP4 it is:
     *   src_addr[4] dst_addr[4] src_port[2] dst_port[2]
     * src_addr is already in network byte order — copy directly to out_ip.
     * peeked+16 through peeked+19 are valid because peek_len >= total >= 28. */
    memcpy(out_ip, peeked + 16, 4);

    /* -- Consume the full header from the socket --------------------------
     * MSG_PEEK did NOT consume the bytes.  We must consume the entire header
     * (16 + addr_len bytes) before returning so tntincall sees a clean stream.
     * Use a 256-byte stack buffer in a loop to avoid large stack allocations. */
    while (total > 0) {
        INT chunk = (total < (INT)sizeof(discard)) ? total : (INT)sizeof(discard);
        n = recv(skt, discard, chunk, 0);
        if (n <= 0) {
            /* Incomplete consume means tntincall would see binary garbage.
             * This is fatal — return -1 so the caller closes the socket. */
            trueip_log("TRUEIP v2: consume recv returned %d after reading %d remaining bytes — connection broken",
                       n, total);
            return -1;
        }
        total -= n;
    }

    {
        /* Log the parsed IP using %u.%u.%u.%u byte expansion.
         * WHY NOT inet_ntoa: returns a static buffer — two calls in one log
         * statement produce undefined results (second overwrites first). */
        unsigned char *b = (unsigned char *)&out_ip->s_addr;
        trueip_log("TRUEIP v2: parsed real client IP: %u.%u.%u.%u (addr_len=%d)",
                   b[0], b[1], b[2], b[3], 16 + addr_len);
    }

    return 1;  /* success — *out_ip is valid */
}

/* ============================================================================
 * parse_proxy_header() — detect and parse a PROXY Protocol header (v1 or v2).
 *
 * This is the top-level dispatcher.  It peeks at the incoming bytes and routes:
 *   - First 12 bytes match PROXY_V2_MAGIC → parse_proxy_v2_payload()
 *   - First 6 bytes are "PROXY "          → v1 text parsing (below)
 *   - Neither                             → return 0 (direct connection)
 *
 * PROXY v1 format (text, single line terminated by \r\n):
 *   "PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n"
 *   "PROXY LOCAL\r\n"                     (health check — no IP substitution)
 *
 * ALGORITHM (v1 path):
 *   1. FIONREAD preflight — wait up to 20ms for >= 16 bytes in kernel buffer.
 *      16 bytes is the minimum to distinguish v2 (needs 16) from v1 (>= 14).
 *      NO select/blocking wait beyond the short retry loop — the BBS scheduler
 *      is single-threaded and cannot tolerate blocking in incall().
 *   2. MSG_PEEK — inspect bytes without consuming.  CRITICAL: direct connections
 *      (require_header=NO) must not have their IAC negotiation consumed.
 *   3. v2 magic check — dispatch to parse_proxy_v2_payload() if matched.
 *   4. "PROXY " prefix check — return 0 if not matched (direct connection).
 *   5. Find \r\n terminator within the peeked data.
 *   6. Consume exactly the header bytes (up to and including \r\n).
 *   7. sscanf parse — must return exactly 5 fields for TCP4.
 *   8. Check proto: "LOCAL" → return 0 (health check).
 *                   "TCP4"  → proceed.
 *                   other   → return -1 (unsupported, e.g. TCP6).
 *   9. Strip "::ffff:" prefix (Node.js dual-stack sends IPv4-mapped IPv6).
 *  10. inet_addr conversion — INADDR_NONE means malformed.
 *
 * PARAMETERS:
 *   skt       — the raw socket (clskt value at incall time)
 *   out_ip    — receives the parsed real client IP on success
 *
 * RETURNS:
 *    1 = success, *out_ip filled with the real client IP
 *    0 = not a PROXY header (or PROXY LOCAL health check) — no IP sub
 *   -1 = malformed / unsupported / recv error
 * ============================================================================*/
static INT
parse_proxy_header(INT skt, struct in_addr *out_ip)
{
    CHAR    hdr[PROXY_HEADER_MAX + 1];
    INT     hdr_len    = 0;
    CHAR    proto[16]  = {0};
    CHAR    src_ip[64] = {0};
    CHAR    dst_ip[64] = {0};
    INT     src_port   = 0;
    INT     dst_port   = 0;
    INT     fields;
    CHAR   *ip_ptr;
    ULONG   addr;

    /* -- Step 1: preflight ------------------------------------------------
     * ioctlsocket(FIONREAD) returns bytes waiting in the socket recv buffer.
     * WHY NOT recvbw(): the original GALTCPIP.DLL's recvbw is a dead stub
     * that always returns 0 — using it here would reject every connection.
     *
     * WHY retry loop: incall fires on accept(), before the proxy's PROXY
     * header bytes reach the kernel recv buffer. On LAN the data arrives
     * within 1-2ms. We poll up to 20 times with 1ms sleeps (20ms max).
     * A real reverse proxy (HAProxy, BBSFirewall) sends the header in the
     * first data segment — this loop is belt-and-suspenders for timing. */
    {
        u_long ul_avail = 0;
        INT avail;
        INT retry;
        for (retry = 0; retry < 20; retry++) {
            ioctlsocket(skt, FIONREAD, &ul_avail);
            avail = (INT)ul_avail;
            if (avail >= 16) break;
            Sleep(1);
        }
        if (retry > 0 && avail >= 16) {
            trueip_log("TRUEIP: preflight needed %d ms to see %d bytes", retry, avail);
        }
        INT peek_n;
        INT hdr_end = -1;
        INT i;

        if (avail < 16) {
            trueip_log("TRUEIP: recvbw=%d < 16 on socket %d — no PROXY header in buffer", avail, skt);
            return -1;
        }

        /* -- Step 2: MSG_PEEK — look without consuming --------------------
         * CRITICAL: we must NOT consume bytes from a direct connection.
         * If require_header=NO and this is a direct telnet client, consuming
         * the first bytes (IAC negotiation) would corrupt the session.
         * MSG_PEEK lets us inspect without removing from the buffer. */
        if (avail > PROXY_HEADER_MAX) avail = PROXY_HEADER_MAX;
        peek_n = recv(skt, hdr, avail, MSG_PEEK);
        if (peek_n <= 0) {
            trueip_log("TRUEIP: MSG_PEEK recv returned %d", peek_n);
            return -1;
        }
        hdr[peek_n] = '\0';

        /* -- Step 3: detect PROXY v2 binary header ----------------------------
         * v2 is identified by a 12-byte magic signature.  If the first 12 bytes
         * match, dispatch to the v2 parser immediately — it reads family, command,
         * addr_len, extracts src_addr, and consumes the full header from the socket.
         * The v2 check MUST precede the v1 strncmp because the v2 magic begins with
         * \r\n bytes that would not match "PROXY " anyway, but being explicit avoids
         * any ambiguity in edge cases. */
        if (peek_n >= 12 && memcmp(hdr, PROXY_V2_MAGIC, 12) == 0) {
            return parse_proxy_v2_payload(skt, hdr, peek_n, out_ip);
        }

        /* -- Step 4: validate "PROXY " prefix without consuming -----------
         * If the first 6 bytes are NOT "PROXY ", this is a direct connection.
         * Return 0 with ZERO bytes consumed — tntincall gets the full stream. */
        if (strncmp(hdr, "PROXY ", 6) != 0) {
            trueip_log("TRUEIP: no PROXY prefix — direct connection (bytes untouched)");
            return 0;
        }

        /* -- Step 5: find \r\n in peeked data -----------------------------
         * The PROXY header must end with \r\n within the peeked bytes.
         * If \r\n is not found, the header is incomplete (partial TCP delivery). */
        for (i = 0; i < peek_n - 1; i++) {
            if (hdr[i] == '\r' && hdr[i + 1] == '\n') {
                hdr_end = i + 2;
                break;
            }
        }
        if (hdr_end < 0) {
            trueip_log("TRUEIP: PROXY prefix found but no \\r\\n in %d peeked bytes — incomplete", peek_n);
            return -1;
        }

        /* -- Step 6: consume exactly the header ---------------------------
         * Now that we KNOW a complete PROXY header is in the buffer, consume
         * exactly hdr_end bytes.  Everything after \r\n stays in the buffer
         * for tntincall's telnet negotiation. */
        hdr_len = recv(skt, hdr, hdr_end, 0);
        if (hdr_len <= 0) {
            trueip_log("TRUEIP: consume recv returned %d", hdr_len);
            return -1;
        }
        hdr[hdr_len] = '\0';
    }

    /* -- Step 7: sscanf parse ------------------------------------------
     * "PROXY %15s %63s %63s %d %d"
     * Fields: proto, src_ip, dst_ip, src_port, dst_port.
     * Must return exactly 5 for TCP4; fewer fields means LOCAL or malformed. */
    fields = sscanf(hdr, "PROXY %15s %63s %63s %d %d",
                    proto, src_ip, dst_ip, &src_port, &dst_port);

    /* -- Step 8: check protocol field ------------------------------------*/
    if (fields == 1 && strncmp(proto, "LOCAL", 5) == 0) {
        /* PROXY LOCAL is a HAProxy health-check connection.  The spec says
         * we should not perform IP substitution — treat it as a direct
         * connection and let the caller decide (g_require_header governs). */
        trueip_log("TRUEIP: PROXY LOCAL health check received — no IP substitution");
        return 0;
    }

    if (fields < 5) {
        trueip_log("TRUEIP: sscanf returned %d fields (expected 5) — malformed header", fields);
        return -1;
    }

    if (strncmp(proto, "TCP4", 4) != 0) {
        /* TCP6 and UNKNOWN are not supported.  TCP6 requires full IPv6
         * parsing that GALTCPIP does not support (tcpipinf.inaddr is
         * struct in_addr — 32-bit only).  Log and reject. */
        trueip_log("TRUEIP: unsupported PROXY protocol '%s' (only TCP4 is supported)", proto);
        return -1;
    }

    /* -- Step 9: strip ::ffff: prefix ------------------------------------
     * Node.js running on a dual-stack socket sends IPv4-mapped IPv6 addresses:
     * "::ffff:203.0.113.42".  Strip the prefix so inet_addr() can parse it.
     * This is the BBSFirewall case — Mark's proxy-protocol.js strips it on the
     * send side too, but we handle it here for belt-and-suspenders safety. */
    ip_ptr = src_ip;
    if (strncmp(ip_ptr, "::ffff:", 7) == 0) {
        ip_ptr += 7;  /* advance past the mapped-IPv6 prefix */
        trueip_log("TRUEIP: stripped ::ffff: prefix, real src_ip='%s'", ip_ptr);
    }

    /* -- Step 10: inet_addr conversion -----------------------------------
     * inet_addr() returns INADDR_NONE (0xFFFFFFFF) for malformed input.
     * The TCPIP.H header redefines INADDR_NONE to 0xFFFFFFFFL to avoid a
     * Borland compiler warning — use that constant. */
    addr = inet_addr(ip_ptr);
    if (addr == INADDR_NONE) {
        trueip_log("TRUEIP: inet_addr('%s') returned INADDR_NONE — malformed IP in PROXY header", ip_ptr);
        return -1;
    }

    out_ip->s_addr = addr;

    {
        /* Log the real IP using %u.%u.%u.%u byte expansion.
         * WHY NOT inet_ntoa: inet_ntoa() returns a pointer to a STATIC buffer
         * inside winsock.  Two calls in one log statement produce undefined
         * results (the second call overwrites the first's buffer). */
        unsigned char *b = (unsigned char *)&out_ip->s_addr;
        trueip_log("TRUEIP: parsed PROXY header — real client IP: %u.%u.%u.%u src_port=%d",
                   b[0], b[1], b[2], b[3], src_port);
    }

    return 1;  /* success — *out_ip is valid */
}

/* ============================================================================
 * trueip_incall() — TCP accept callback for the proxy port.
 *
 * Called by GALTCPIP on the BBS scheduler thread every time a connection
 * is accepted on the proxy listener port (the one configured via TPORT).
 *
 * PARAMETER:
 *   gotchn — channel assignment from GALTCPIP.  TCPIP.H comments are
 *            contradictory (svrinf says "1/0", regtcpsvr says "usrnum/-1").
 *            We guard both: gotchn <= 0 means "no channel available".
 *
 * IMPLICIT INPUTS (GALTCPIP sets before calling us):
 *   clskt  — the accepted socket handle
 *   claddr — the peer's sockaddr_in (contains the proxy's IP, NOT the real one)
 *
 * SOCKET OWNERSHIP RULE:
 *   Before tntincall(): socket belongs to us — close with clsskt() on error.
 *   After tntincall():  socket belongs to GALTNTD — NEVER close it.
 *   Violating this rule causes a double-close that corrupts GALTCPIP's
 *   socket event notification table (sktmap) and causes undefined behavior
 *   on the next scheduler select() cycle.
 * ============================================================================*/
static VOID __cdecl
trueip_incall(INT gotchn)
{
    struct in_addr  real_ip;
    INT             parse_rc;
    CHAR            detail[AUDDETSIZ];   /* AUDDETSIZ = 128; never exceed this */
    unsigned char  *pb;                  /* byte pointer for IP formatting      */
    unsigned char  *src_pb;             /* source IP bytes for logging          */

    g_conn_total++;

    /* -- Guard: no channel available ------------------------------------
     * gotchn <= 0 means GALTCPIP could not assign a BBS channel (all slots
     * are occupied, or the BBS is shutting down).  We must NOT pass this
     * to tntincall() — that would hand a failure indicator to the telnet
     * daemon and the result is undefined behavior.  Close our socket and bail. */
    if (gotchn <= 0) {
        {
            unsigned char *b = (unsigned char *)&claddr.sin_addr.s_addr;
            trueip_log("TRUEIP: gotchn=%d (no channel) from %u.%u.%u.%u — clsskt and return",
                       gotchn, b[0], b[1], b[2], b[3]);
        }
        clsskt(clskt);  /* WHY clsskt not closesocket: see file header */
        return;
    }

    /* -- Rate limit check -----------------------------------------------
     * A connection flood on the proxy port can starve the single-threaded
     * scheduler.  Check before any heavier processing. */
    if (!check_rate_limit()) {
        {
            unsigned char *b = (unsigned char *)&claddr.sin_addr.s_addr;
            CHAR warn[256];
            _snprintf(warn, sizeof(warn) - 1,
                      "TRUEIP: rate limit exceeded (%d/sec) — dropped connection from %u.%u.%u.%u",
                      g_max_conn_per_sec, b[0], b[1], b[2], b[3]);
            warn[sizeof(warn) - 1] = '\0';
            /* Rate-limit events go to Event Log as WARNING (not INFO) so
             * administrators can detect connection floods. */
            trueip_event_log(EVENTLOG_WARNING_TYPE, warn);
            if (g_log_enabled) {
                trueip_log("%s", warn);
            }
        }
        g_conn_rate_limited++;
        clsskt(clskt);
        return;
    }

    /* -- Trusted source check ------------------------------------------
     * claddr is set by GALTCPIP before calling us — it is the proxy's IP.
     * If the trusted list is non-empty, reject connections from unknown sources.
     * An untrusted source could send a forged PROXY header claiming any IP,
     * allowing IP spoofing.  This is defense-in-depth; the Windows Firewall
     * rule on port 2324 is the primary security boundary. */
    if (!is_trusted_source(claddr.sin_addr.s_addr)) {
        {
            unsigned char *b = (unsigned char *)&claddr.sin_addr.s_addr;
            CHAR warn[256];
            _snprintf(warn, sizeof(warn) - 1,
                      "TRUEIP: untrusted source %u.%u.%u.%u — rejected (not in TRUSTIP list)",
                      b[0], b[1], b[2], b[3]);
            warn[sizeof(warn) - 1] = '\0';
            trueip_event_log(EVENTLOG_WARNING_TYPE, warn);
            if (g_log_enabled) {
                trueip_log("%s", warn);
            }
        }
        g_conn_rejected_ip++;
        clsskt(clskt);
        return;
    }

    /* -- Parse PROXY header (v1 text or v2 binary) --------------------*/
    memset(&real_ip, 0, sizeof(real_ip));
    parse_rc = parse_proxy_header(clskt, &real_ip);

    if (parse_rc < 0) {
        /* Malformed header, recv error, or unsupported protocol.
         * Log and reject.  clsskt here because we haven't called tntincall. */
        {
            unsigned char *b = (unsigned char *)&claddr.sin_addr.s_addr;
            trueip_log("TRUEIP: bad/malformed PROXY header from %u.%u.%u.%u — rejected",
                       b[0], b[1], b[2], b[3]);
        }
        g_conn_rejected_header++;
        clsskt(clskt);
        return;
    }

    if (parse_rc == 0) {
        /* No PROXY header found (or PROXY LOCAL health check).
         * Behavior depends on g_require_header config. */
        if (g_require_header) {
            /* Production default: reject connections without a PROXY header.
             * Direct connections should go to port 23, not the proxy port. */
            {
                unsigned char *b = (unsigned char *)&claddr.sin_addr.s_addr;
                trueip_log("TRUEIP: no PROXY header from %u.%u.%u.%u and REQHDR=YES — rejected",
                           b[0], b[1], b[2], b[3]);
            }
            g_conn_rejected_header++;
            clsskt(clskt);
            return;
        } else {
            /* REQHDR=NO: allow direct connections without IP substitution.
             * Useful for testing: connect directly to the proxy port and get
             * a normal BBS session.  Not recommended in production. */
            {
                unsigned char *b = (unsigned char *)&claddr.sin_addr.s_addr;
                trueip_log("TRUEIP: no PROXY header from %u.%u.%u.%u — REQHDR=NO, passing through",
                           b[0], b[1], b[2], b[3]);
            }
            tntincall(gotchn);
            /* Socket now owned by GALTNTD — do NOT close it. */
            return;
        }
    }

    /* -- parse_rc == 1: valid PROXY header, real_ip is set --------------
     *
     * Call tntincall() to create the BBS telnet session.  After it returns,
     * usrnum is the assigned channel index.
     *
     * WHY tntincall is synchronous and usrnum is valid after return:
     *   Confirmed by federation_recon_mod.c: fed_poc_incall() captures usrnum
     *   immediately after tntincall(gotchn) returns (g_fed_pending_channel = usrnum).
     *   tntincall() writes tcpipinf[usrnum].inaddr = claddr.sin_addr (the proxy IP)
     *   during its execution, then returns.  Our write AFTER the return is the
     *   final write — no subsequent host code re-reads claddr.
     *
     * *** AFTER THIS CALL THE SOCKET BELONGS TO GALTNTD ***
     * *** NEVER CALL clsskt(clskt) AFTER THIS POINT ***
     */
    tntincall(gotchn);

    /* -- Overwrite tcpipinf[usrnum].inaddr with the real client IP ------
     *
     * Guard usrnum range before touching the array.  If tntincall somehow
     * failed to assign a valid slot (channel exhaustion edge case), usrnum
     * may be out of range.  We skip the write rather than crash — the socket
     * is still GALTNTD's and we cannot close it.
     *
     * WHY this write is safe (4 points):
     *   1. tntincall is synchronous — it's done before we reach this line.
     *   2. Our write is the final write to this field — no host code
     *      subsequently re-reads claddr and overwrites us.
     *   3. struct in_addr is 4 bytes — naturally atomic on x86.
     *   4. The BBS scheduler is single-threaded — no concurrent readers
     *      can be accessing this slot at this instant. */
    if (usrnum < 0 || usrnum >= nterms) {
        trueip_log("TRUEIP: WARNING — tntincall returned invalid usrnum=%d (nterms=%d); "
                   "skipping tcpipinf write (socket still owned by GALTNTD)",
                   usrnum, nterms);
        /* Do NOT close the socket. GALTNTD owns it even on failure. */
        return;
    }

    /* THE KEY WRITE — all IP consumers now see the real client IP. */
    tcpipinf[usrnum].inaddr = real_ip;

    /* -- Audit trail entry ----------------------------------------------
     * We write our own authoritative audit entry with the REAL IP.
     * Note: GALTCPIP may have already written an entry with the proxy IP
     * (controlled by the audinc flag).  Our entry is the canonical one.
     *
     * _snprintf with explicit limit 128 — AUDDETSIZ is exactly 128 bytes.
     * Exceeding it corrupts adjacent memory (the detail field is a fixed
     * char array in the struct audEntry). */
    pb = (unsigned char *)&real_ip.s_addr;
    src_pb = (unsigned char *)&claddr.sin_addr.s_addr;

    _snprintf(detail, AUDDETSIZ - 1,
              "chan %d real=%u.%u.%u.%u proxy=%u.%u.%u.%u",
              usrnum,
              pb[0],  pb[1],  pb[2],  pb[3],
              src_pb[0], src_pb[1], src_pb[2], src_pb[3]);
    detail[AUDDETSIZ - 1] = '\0';

    if (g_hAuditTrail != NULL && g_pfn_audfAddEntry != NULL) {
        g_pfn_audfAddEntry(g_hAuditTrail, "TRUEIP", "%s", detail);
    }

    /* -- Success logging ------------------------------------------------*/
    trueip_log("TRUEIP: chan=%d proxied — real IP %u.%u.%u.%u via proxy %u.%u.%u.%u",
               usrnum,
               pb[0],  pb[1],  pb[2],  pb[3],
               src_pb[0], src_pb[1], src_pb[2], src_pb[3]);

    g_conn_proxied++;
}

/* ============================================================================
 * trueip_global_handler() — sysop command handler registered via globalcmd().
 *
 * WHY globalcmd:
 *   globalcmd() registers a handler that the BBS scheduler calls when the
 *   sysop types a command at the BBS main menu prompt.  This is separate from
 *   module menus (which require a user to "enter" the module).  It is the
 *   standard MBBS10 mechanism for sysop management commands.
 *
 * COMMANDS:
 *   TRUEIP          — print version banner
 *   TRUEIP STATUS   — print full module state and connection counters
 *
 * RETURNS:
 *   -2 = command consumed and output ready to flush (BBS flushes prf buffer)
 *    0 = not our command (pass to next global handler in chain)
 * ============================================================================*/
static INT __cdecl
trueip_global_handler(VOID)
{
    /* g_pmargv mirrors the SDK margv[] array — resolved via GetProcAddress.
     * Guard against NULL before indexing (would be NULL only if WGSERVER
     * didn't export _margv, which should never happen on a real BBS). */
    if (g_pmargv == NULL) {
        return 0;
    }

    /* /IP — show all active TCP/IP connections */
    if (sameas(g_pmargv[0], "/IP")) {
        if (g_pfn_prf && g_pfn_setmbk && g_pfn_getMsgBlk && g_pfn_rstmbk) {
            INT slot, count = 0;
            char *hdr, *rowfmt;

            g_pfn_setmbk(g_mcv);
            hdr    = g_pfn_getMsgBlk(TRUEIP_WHOHDR);
            rowfmt = g_pfn_getMsgBlk(TRUEIP_WHOROW);
            g_pfn_rstmbk();

            shocst("TRUEIP-DBG", "rowfmt=%p hdr=%p", rowfmt, hdr);
            if (rowfmt) shocst("TRUEIP-DBG", "rowfmt len=%d first4=0x%02X%02X%02X%02X",
                (int)strlen(rowfmt),
                (unsigned char)rowfmt[0], (unsigned char)rowfmt[1],
                (unsigned char)rowfmt[2], (unsigned char)rowfmt[3]);

            if (!rowfmt || !rowfmt[0] || rowfmt == hdr) rowfmt = " %4d  %-18s%-7d%-19s";
            if (hdr) g_pfn_prf("%s\r\n", hdr);

            for (slot = 0; slot < nterms; slot++) {
                char *entry = (char *)tcpipinf + slot * 0xD8;
                int skt = *(int *)(entry + 0xB4);
                if (skt != 0 && skt != -1) {
                    struct in_addr ip = *(struct in_addr *)(entry + 0xAC);
                    int port = *(int *)(entry + 0xB0);
                    struct svrinf *svr = *(struct svrinf **)(entry + 0xA8);
                    unsigned char *b = (unsigned char *)&ip.s_addr;
                    char ipbuf[20];
                    char svrname[20];
                    _snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
                    ipbuf[sizeof(ipbuf)-1] = '\0';
                    _snprintf(svrname, sizeof(svrname), "%s", (svr && svr->name) ? svr->name : "?");
                    svrname[sizeof(svrname)-1] = '\0';
                    g_pfn_prf(rowfmt, slot, ipbuf, port, svrname);
                    g_pfn_prf("\r\n");
                    count++;
                }
            }

            g_pfn_prf("\x1b[0m %d connection(s)\r\n", count);
        }
        return -2;
    }

    if (!sameas(g_pmargv[0], "TRUEIP")) {
        return 0;  /* Not /IP or TRUEIP — let other modules check. */
    }

    if (g_pmargv[1] != NULL && sameas(g_pmargv[1], "DUMP")) {
        /* TRUEIP DUMP — raw tcpipinf diagnostic for debugging */
        if (g_pfn_prf) {
            INT slot;
            g_pfn_prf("tcpipinf=%p nterms=%d stride=0xD8 usrnum=%d\r\n",
                      tcpipinf, nterms, usrnum);
            for (slot = 0; slot < 10 && slot < nterms; slot++) {
                char *e = (char *)tcpipinf + slot * 0xD8;
                int skt  = *(int *)(e + 0xB4);
                int unum = *(int *)(e + 0xB8);
                int port = *(int *)(e + 0xB0);
                struct in_addr ip = *(struct in_addr *)(e + 0xAC);
                void *svr = *(void **)(e + 0xA8);
                unsigned char *b = (unsigned char *)&ip.s_addr;
                g_pfn_prf("[%d] skt=0x%08X unum=%d ip=%u.%u.%u.%u port=%d svr=%p\r\n",
                          slot, skt, unum, b[0], b[1], b[2], b[3], port, svr);
            }
        }
        return -2;
    }

    if (g_pmargv[1] == NULL || g_pmargv[1][0] == '\0' ||
        (!sameas(g_pmargv[1], "STATUS"))) {
        /* No subcommand or unrecognized subcommand — print one-line banner. */
        if (g_pfn_prf) {
            g_pfn_prf("TRUEIP v%s -- PROXY Protocol v1 for MBBS10\r\n", TRUEIP_VERSION);
            g_pfn_prf("  Commands: TRUEIP STATUS | /IP\r\n");
        }
        return -2;
    }

    /* TRUEIP STATUS — full module state display. */
    if (g_pfn_prf) {
        INT i;

        g_pfn_prf("TRUEIP v%s\r\n", TRUEIP_VERSION);
        g_pfn_prf("  Port: %-5d  Listener: %s\r\n",
                  g_proxy_port,
                  g_server_ok ? "ACTIVE" : "FAILED (port conflict?)");
        g_pfn_prf("  Require PROXY header: %s\r\n", g_require_header ? "YES" : "NO");

        if (g_trusted_ip_count > 0) {
            g_pfn_prf("  Trusted IPs (%d): ", g_trusted_ip_count);
            for (i = 0; i < g_trusted_ip_count; i++) {
                g_pfn_prf("%s%s", g_trusted_ips[i],
                          (i < g_trusted_ip_count - 1) ? ", " : "");
            }
            g_pfn_prf("\r\n");
        } else {
            g_pfn_prf("  Trusted IPs: (none -- any source accepted)\r\n");
        }

        g_pfn_prf("  Rate limit: %d/sec   Debug log: %s\r\n",
                  g_max_conn_per_sec,
                  g_log_enabled ? "ON" : "OFF");

        g_pfn_prf("  Connections: total=%-6lu  proxied=%-6lu\r\n",
                  (unsigned long)g_conn_total,
                  (unsigned long)g_conn_proxied);

        g_pfn_prf("  Rejected:    header=%-4lu  ip=%-4lu  rate=%-4lu\r\n",
                  (unsigned long)g_conn_rejected_header,
                  (unsigned long)g_conn_rejected_ip,
                  (unsigned long)g_conn_rate_limited);
    }

    return -2;
}

/* ============================================================================
 * trueip_shutdown() — finrou callback: BBS is shutting down.
 *
 * Called by the BBS scheduler when wgserver.exe is performing its graceful
 * shutdown sequence (after all users have been disconnected).
 *
 * WHY we can't unregister the TCP server:
 *   regtcpsvr() has no corresponding unregister API.  GALTCPIP closes all
 *   listening sockets and cleans up svrhead on process exit.
 * ============================================================================*/
static VOID
trueip_shutdown(VOID)
{
    CHAR msg[512];

    /* Write final connection counters to the Event Log so administrators
     * have a session-summary record in Event Viewer after each restart. */
    _snprintf(msg, sizeof(msg) - 1,
              "TRUEIP v%s shutdown — "
              "total=%lu proxied=%lu rej_hdr=%lu rej_ip=%lu rate_lim=%lu",
              TRUEIP_VERSION,
              (unsigned long)g_conn_total,
              (unsigned long)g_conn_proxied,
              (unsigned long)g_conn_rejected_header,
              (unsigned long)g_conn_rejected_ip,
              (unsigned long)g_conn_rate_limited);
    msg[sizeof(msg) - 1] = '\0';

    shocst("TRUEIP", "%s", msg);
    trueip_event_log(EVENTLOG_INFORMATION_TYPE, msg);

    /* Close the MCV config file.
     * clsmsg is name-resolved via g_pfn_clsmsg — guard before calling. */
    if (g_mcv != NULL) {
        if (g_pfn_clsmsg) g_pfn_clsmsg(g_mcv);
        g_mcv = NULL;
    }

    /* Deregister from the Windows Event Log. */
    if (g_hEventLog != NULL) {
        DeregisterEventSource(g_hEventLog);
        g_hEventLog = NULL;
    }
}

/* ============================================================================
 * init__trueip() — DLL entry point, called by the BBS at module load time.
 *
 * EXPORT macro = __declspec(dllexport), matching V10MOD.C pattern.
 * Only init__trueip has EXPORT — other functions are reached via the module
 * interface block (function pointers), not by name.
 *
 * SEQUENCE:
 *   1. Register module (required for module table, LANCE, WGSETUP)
 *   2. Open Event Log source (early — used by subsequent log calls)
 *   3. Read MCV config (port, require_header, trusted IPs, rate limit, logging)
 *   4. Register global sysop command handler
 *   5. Bind proxy port TCP listener via regtcpsvr()
 *   6. Log startup banner
 * ============================================================================*/
void EXPORT
init__trueip(VOID)
{
    CHAR banner[256];

    /* -- Step 1: resolve ALL host APIs via GetProcAddress ------------------
     *
     * MUST run BEFORE calling register_module/gmdnam/stzcpy — those are
     * among the 9 named-import fixes and are only safe to call via g_pfn_
     * pointers after this block completes.
     *
     * WHY GetProcAddress for all these symbols (not just audfAddEntry):
     *
     * WHY GetProcAddress for all these symbols (not just audfAddEntry):
     *   WGSERVER.EXE exports every C function with a leading underscore per
     *   the x86 __cdecl ABI (e.g. "_register_module").  The SDK import library
     *   WGSERVER_LIB.LIB strips the underscore in its linker stubs — so when
     *   the loader resolves the DLL import table it looks for "register_module"
     *   and gets ERROR_PROC_NOT_FOUND (0x7F) because the real export is
     *   "_register_module".
     *
     *   The cure: never let these 9 symbols appear in the IAT.  We resolve
     *   them here using the raw (underscored) export names that GetProcAddress
     *   reads directly from the export directory.
     *
     *   Ordinal-resolved symbols (usrnum, nterms, shocst, sameas, opnmsg,
     *   numopt, ynopt, stgopt, regtcpsvr, etc.) are unaffected — ordinal
     *   lookup bypasses name matching entirely.
     *
     * CRITICAL: the underscore prefix in each GetProcAddress string is
     * REQUIRED.  GetProcAddress reads the raw export directory name from
     * WGSERVER.EXE — the leading underscore is part of the C-decorated name
     * and must be present.  Omitting it returns NULL every time.
     */
    {
        HMODULE hWgs = GetModuleHandleA("WGSERVER.EXE");
        if (hWgs) {
            /* Optional audit/global APIs — may be absent in some SDK builds. */
            g_pfn_audfAddEntry = (pfn_audfAddEntry)GetProcAddress(hWgs, "_audfAddEntry");
            g_pfn_globalcmd    = (pfn_globalcmd)GetProcAddress(hWgs, "_globalcmd");
            g_hAuditTrail      = *(void**)GetProcAddress(hWgs, "_hAuditTrail");

            /* Named-import fixes — these MUST be resolved here instead of via
             * the import table.  See the WHY block above. */
            g_pfn_register_module = (pfn_register_module)GetProcAddress(hWgs, "_register_module");
            g_pfn_gmdnam          = (pfn_gmdnam)         GetProcAddress(hWgs, "_gmdnam");
            g_pfn_prf             = (pfn_prf)            GetProcAddress(hWgs, "_prf");
            g_pfn_stzcpy          = (pfn_stzcpy)         GetProcAddress(hWgs, "_stzcpy");
            g_pfn_rstmbk          = (pfn_rstmbk)         GetProcAddress(hWgs, "_rstmbk");
            g_pfn_setmbk          = (pfn_setmbk)         GetProcAddress(hWgs, "_setmbk");
            g_pfn_clsmsg          = (pfn_clsmsg)         GetProcAddress(hWgs, "_clsmsg");
            g_pfn_outprf          = (pfn_outprf)         GetProcAddress(hWgs, "_outprf");
            g_pfn_getMsgBlk       = (pfn_getMsgBlk)      GetProcAddress(hWgs, "_getMsgBlk");

            /* margv is a DATA global (char** base of the arg-word array).
             * GetProcAddress returns a pointer to the export — for a DATA export
             * that is the address of the variable itself.  We cast to char** so
             * call sites can index it: g_pmargv[0] == margv[0]. */
            g_pmargv = (char**)GetProcAddress(hWgs, "_margv");

            /* Log any missing symbols — absence is not fatal (module still loads)
             * but the operator should know immediately if a core API is missing. */
            if (!g_pfn_register_module) shocst("TRUEIP", "WARNING: _register_module not found in WGSERVER.EXE");
            if (!g_pfn_gmdnam)          shocst("TRUEIP", "WARNING: _gmdnam not found in WGSERVER.EXE");
            if (!g_pfn_prf)             shocst("TRUEIP", "WARNING: _prf not found in WGSERVER.EXE");
            if (!g_pfn_stzcpy)          shocst("TRUEIP", "WARNING: _stzcpy not found in WGSERVER.EXE");
            if (!g_pfn_rstmbk)          shocst("TRUEIP", "WARNING: _rstmbk not found in WGSERVER.EXE");
            if (!g_pfn_setmbk)          shocst("TRUEIP", "WARNING: _setmbk not found in WGSERVER.EXE");
            if (!g_pfn_clsmsg)          shocst("TRUEIP", "WARNING: _clsmsg not found in WGSERVER.EXE");
            if (!g_pfn_outprf)          shocst("TRUEIP", "WARNING: _outprf not found in WGSERVER.EXE");
            if (!g_pmargv)              shocst("TRUEIP", "WARNING: _margv not found in WGSERVER.EXE");
        } else {
            /* WGSERVER.EXE is always the host process — if GetModuleHandle fails
             * something is deeply wrong.  Log and continue (non-fatal). */
            shocst("TRUEIP", "WARNING: GetModuleHandleA(WGSERVER.EXE) returned NULL — GetProcAddress skipped");
        }
    }

    /* -- Step 1a: register module (now safe — g_pfn_ pointers are filled) --
     * gmdnam() reads the "Module Name:" field from TRUEIP.MDF.
     * stzcpy() is the SDK's safe string copy with NUL fill (like strlcpy).
     * register_module() inserts us into the BBS module table.
     *
     * All three are called through their g_pfn_ pointers because they are
     * among the 9 named-import symbols that fail via the import library. */
    if (g_pfn_stzcpy && g_pfn_gmdnam) {
        g_pfn_stzcpy(TRUEIP.descrp, g_pfn_gmdnam("TRUEIP.MDF"), MNMSIZ);
    } else {
        /* Fallback: copy a literal name so the module is at least identifiable
         * in LANCE/WGSETUP even if gmdnam/stzcpy couldn't be resolved. */
        strncpy(TRUEIP.descrp, "TRUEIP Proxy", MNMSIZ - 1);
        TRUEIP.descrp[MNMSIZ - 1] = '\0';
    }
    if (g_pfn_register_module) {
        usrstt_trueip = g_pfn_register_module(&TRUEIP);
    }

    /* -- Step 2: Windows Event Log --------------------------------------
     * RegisterEventSource opens a connection to the Windows Application Event
     * Log and creates a "TRUEIP" source.  The source appears in Event Viewer,
     * PowerShell Get-WinEvent, Splunk, SCOM, etc.  No .mc message file needed
     * for basic ReportEvent with string arrays. */
    g_hEventLog = RegisterEventSourceA(NULL, "TRUEIP");
    if (g_hEventLog == NULL) {
        /* shocst() writes to the BBS sysop console (the text-mode status area).
         * Use it for startup messages before g_log_enabled is known. */
        shocst("TRUEIP", "WARNING: RegisterEventSource failed (err=%lu) — Event Log disabled",
               (unsigned long)GetLastError());
    }

    /* -- Step 3: read MCV config ----------------------------------------
     * opnmsg() opens the compiled .MCV file (produced by WGSCNF from TRUEIP.MSG).
     * setmbk() makes it the active message block for ynopt/numopt/stgopt calls.
     * rstmbk() restores the previous message block when we're done.
     *
     * If the MCV is absent (not yet configured by sysop), we use compiled
     * defaults and log a warning.  The module is still functional with defaults. */
    g_mcv = opnmsg("TRUEIP.MCV");
    if (g_mcv != NULL) {
        /* setmbk/rstmbk are name-resolved via g_pfn_ — guard before calling. */
        if (g_pfn_setmbk) g_pfn_setmbk(g_mcv);

        /* numopt(msgnum, floor, ceiling) — reads an integer from the MCV
         * and clamps it to [floor, ceiling].  Returns the clamped value. */
        g_proxy_port       = numopt(TRUEIP_TPORT,    1,   65535);
        g_require_header   = ynopt(TRUEIP_REQHDR);
        g_max_conn_per_sec = numopt(TRUEIP_MAXRATE,  0,   999);
        g_log_enabled      = ynopt(TRUEIP_LOGEN);

        /* stgopt() returns a newly allocated CHAR* — SDK allocates it. */
        g_trusted_ip_str   = stgopt(TRUEIP_TRUSTIP);

        if (g_log_enabled) {
            g_max_log_kb   = numopt(TRUEIP_LOGMAX,   0,   99999);
        }

        if (g_pfn_rstmbk) g_pfn_rstmbk();
        shocst("TRUEIP", "config loaded from TRUEIP.MCV (port=%d)", g_proxy_port);
    } else {
        /* No MCV — defaults are in effect.  This is normal on first install
         * before the sysop runs WGSCNF to configure the module. */
        shocst("TRUEIP", "WARNING: TRUEIP.MCV not found; using compiled defaults "
               "(port=%d, require_header=%s)",
               g_proxy_port, g_require_header ? "YES" : "NO");
        trueip_event_log(EVENTLOG_WARNING_TYPE,
                         "TRUEIP: TRUEIP.MCV not found; using defaults. "
                         "Run WGSCNF to configure the module.");
    }

    /* Parse the trusted IP list from the config string. */
    parse_trusted_ips(g_trusted_ip_str);

    /* -- Port conflict guard -------------------------------------------
     * The proxy port must NOT be 23 (the stock telnet port — GALTNTD already
     * owns it).  regtcpsvr would fail at bind() and the module would be silent.
     * Log explicitly so the operator knows exactly why. */
    if (g_proxy_port == 23) {
        shocst("TRUEIP", "ERROR: TPORT=23 conflicts with the built-in Telnet port. "
               "Configure a different port (e.g. 2324) in WGSCNF.");
        trueip_event_log(EVENTLOG_ERROR_TYPE,
                         "TRUEIP: TPORT=23 conflicts with GALTNTD. "
                         "Change TPORT in WGSCNF (e.g. to 2324) and restart the BBS.");
        /* Module is registered but no listener — incall will never fire. */
        return;
    }

    /* -- Step 4: register global sysop command handler -----------------
     * globalcmd() adds our handler to the chain that the BBS checks when the
     * sysop types at the system-level prompt.  Our handler checks margv[0]
     * for "TRUEIP" and ignores anything else (returns 0). */
    if (g_pfn_globalcmd != NULL) {
        g_pfn_globalcmd(trueip_global_handler);
    }

    /* -- Step 5: bind proxy port TCP listener ---------------------------
     * regtcpsvr() creates a listen socket on g_proxy_port and registers
     * trueip_incall as the incall handler.  The BBS scheduler calls
     * trueip_incall() whenever a connection is accepted.
     * Returns: 1=success, 0=failure (port conflict, bind error, etc.). */
    g_server_ok = regtcpsvr("TRUEIP", g_proxy_port, 5, trueip_incall);

    /* -- Step 6: startup banner ----------------------------------------*/
    if (g_server_ok) {
        _snprintf(banner, sizeof(banner) - 1,
                  "TRUEIP v%s — PROXY Protocol v1 listener active on port %d",
                  TRUEIP_VERSION, g_proxy_port);
        banner[sizeof(banner) - 1] = '\0';
        shocst("TRUEIP", "%s", banner);
        trueip_event_log(EVENTLOG_INFORMATION_TYPE, banner);
    } else {
        _snprintf(banner, sizeof(banner) - 1,
                  "TRUEIP v%s — FAILED to bind port %d "
                  "(port conflict? run 'netstat -ano | findstr %d')",
                  TRUEIP_VERSION, g_proxy_port, g_proxy_port);
        banner[sizeof(banner) - 1] = '\0';
        shocst("TRUEIP", "%s", banner);
        trueip_event_log(EVENTLOG_ERROR_TYPE, banner);
        /* Module is registered but no listener — incall will never fire.
         * The BBS continues running; connections to g_proxy_port are refused. */
    }
}

/* end of trueip.c */
