/*
 * trueip.h -- TRUEIP MBBS10 module public header
 *
 * Purpose: Declares the module version string and the MSG-file message number
 *          constants used by trueip.c to read sysop-configured options from
 *          TRUEIP.MCV (compiled from TRUEIP.MSG by WGSCNF).
 *
 * Invariants:
 *   - Message numbers MUST match the sequential keyword order in TRUEIP.MSG.
 *   - If MSG entries are added/removed/reordered, regenerate these constants.
 *   - All identifiers are prefixed TRUEIP_ to avoid collisions with other
 *     modules loaded into the same wgserver address space.
 *
 * Dependencies: none (pure preprocessor definitions, safe to include anywhere)
 */

#ifndef TRUEIP_H
#define TRUEIP_H

/* ---------------------------------------------------------------------------
 * Module version string — bump on every release.
 * --------------------------------------------------------------------------*/
#define TRUEIP_VERSION "1.0.0"

/* ---------------------------------------------------------------------------
 * TRUEIP.MSG message number constants
 *
 * Each constant is the 1-based sequential index of a keyword entry in
 * TRUEIP.MSG, counting both LEVEL4 options and LEVEL6 text blocks in
 * file order.  Passed to ynopt()/numopt()/stgopt()/prfmsg() to read
 * the corresponding value from the compiled TRUEIP.MCV.
 *
 * MSG entry order:
 *   1  TPORT    N  — proxy listener port (default 2324)
 *   2  REQHDR   B  — require PROXY header? (default YES)
 *   3  TRUSTIP  S  — trusted proxy IPs, comma-separated
 *   4  MAXRATE  N  — max connections/sec (default 10)
 *   5  LOGEN    B  — enable debug file log? (default NO)
 *   6  LOGMAX   N  — max log size KB (default 1024, conditional on LOGEN)
 *   7  SPLASH   T  — LEVEL6 splash text block
 *   8  WHOHDR   T  — WHO command ANSI header (sysop designs in WGSCNF)
 *   9  WHOROW   T  — WHO row format (%4d=chan %-18s=IP %-7d=port %-19s=server)
 * --------------------------------------------------------------------------*/
/* numopt/ynopt/stgopt/getMsgBlk skip LEVEL entries and the language header.
 * Verified: numopt(1)=TPORT worked, getMsgBlk(8)=WHOHDR confirmed by debug. */
#define TRUEIP_TPORT     1    /* N: proxy listener port                    */
#define TRUEIP_REQHDR    2    /* B: require PROXY header                   */
#define TRUEIP_TRUSTIP   3    /* S: trusted proxy IPs (comma-separated)    */
#define TRUEIP_MAXRATE   4    /* N: max connections/sec                    */
#define TRUEIP_LOGEN     5    /* B: enable debug file log                  */
#define TRUEIP_LOGMAX    6    /* N: max log size KB (conditional on LOGEN) */
#define TRUEIP_SPLASH    7    /* T: LEVEL6 splash text block               */
#define TRUEIP_WHOHDR    8    /* T: WHO command ANSI header                */
#define TRUEIP_WHOROW    9    /* T: WHO row format string                  */

#endif /* TRUEIP_H */
