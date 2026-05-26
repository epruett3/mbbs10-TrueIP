@echo off
rem =============================================================================
rem build_trueip.bat -- Build TRUEIP.DLL from source
rem
rem PURPOSE:
rem   Compiles trueip.c and links it against the MBBS10 SDK import libraries
rem   to produce TRUEIP.DLL -- the PROXY Protocol v1 module that ships alongside
rem   GALTCPIP.DLL (does NOT replace it).
rem
rem PREREQUISITES:
rem   Visual Studio 2022 Build Tools (x86 toolchain) must be installed at:
rem     C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\
rem   The SDK import libraries must be in:
rem     external\mbbs-sdk\lib\importlibs\
rem   Required libs: WGSERVER_LIB.LIB  GALGSBL_LIB.LIB  GALTCPIP_LIB.LIB
rem                  GALTNTD_LIB.LIB
rem   tntincall is from GALTNTD.DLL -- GALTNTD_LIB.LIB is present in the SDK.
rem
rem PREPROCESSOR DEFINES (must match TRUEIP.vcxproj Debug|Win32):
rem   WIN32            -- target OS
rem   GCWINNT          -- Galacticomm Windows NT SDK path
rem   GCMVC            -- Microsoft Visual C++ compiler
rem   BBSVER=1000      -- MBBS10 version identifier
rem   USE_DEF_FILE     -- makes EXPORT=empty, IMPORT=__declspec(dllimport)
rem                       so SDK headers declare symbols as imports (not exports)
rem   __BUILDV10MODULE -- selects V10 module API in server.h / mcvapi.h
rem   _WINSOCK_DEPRECATED_NO_WARNINGS -- suppress inet_addr() deprecation
rem
rem INCLUDE PATH:
rem   external\mbbs-sdk\inc        -- all SDK headers (MAJORBBS.H, TCPIP.H, etc.)
rem   external\mbbs-sdk\inc\msg\v10 -- V10 MSG-format headers
rem
rem LINK LIBRARIES (order matters for the linker):
rem   WGSERVER_LIB.LIB  -- usrnum, nterms, shocst, register_module, etc.
rem   GALGSBL_LIB.LIB   -- btuoba, btucdi, btusrs (indirect via TCPIP.H)
rem   GALTCPIP_LIB.LIB  -- tcpipinf[], clskt, claddr, regtcpsvr, clsskt, recvbw
rem   GALTNTD_LIB.LIB   -- tntincall
rem   ws2_32.lib        -- Winsock 2 (recv, inet_addr, etc.)
rem   advapi32.lib      -- Windows Event Log (RegisterEventSource, ReportEvent)
rem   msvcrt.lib        -- CRT (fopen, fprintf, _vsnprintf, _snprintf)
rem =============================================================================

setlocal

rem -- Locate the x86 MSVC toolchain -----------------------------------------
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist %VCVARS% (
    echo ERROR: vcvarsall.bat not found at %VCVARS%
    echo Install Visual Studio 2022 Build Tools with the C++ workload.
    exit /b 1
)
call %VCVARS% x86
if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed to configure the x86 toolchain.
    exit /b 1
)

rem -- Verify required SDK import libraries exist ----------------------------
set SDK_LIBS=external\mbbs-sdk\lib\importlibs
for %%L in (WGSERVER_LIB.LIB GALGSBL_LIB.LIB GALTCPIP_LIB.LIB GALTNTD_LIB.LIB) do (
    if not exist "%SDK_LIBS%\%%L" (
        echo ERROR: Missing import library: %SDK_LIBS%\%%L
        echo The SDK import libraries must be present before building.
        exit /b 1
    )
)

echo === Compiling trueip.c ===

rem /c            -- compile only, no link
rem /Zp8          -- pack structs on 8-byte boundary (matches original DLL)
rem /W3           -- warning level 3
rem /J            -- char is unsigned by default (Galacticomm convention)
rem /Od           -- disable optimization (debug build)
rem /Zi           -- generate PDB debug info
rem /nologo       -- suppress compiler banner
rem /I            -- additional include paths (SDK headers)

cl /c /Zp8 /W3 /J /Od /Zi /nologo ^
   /D_CRT_SECURE_NO_WARNINGS ^
   /D_CRT_SECURE_NO_DEPRECATE ^
   /D_CRT_NONSTDC_NO_DEPRECATE ^
   /D_WINSOCK_DEPRECATED_NO_WARNINGS ^
   /DWIN32 /DGCWINNT /DGCMVC /DBBSVER=1000 ^
   /DUSE_DEF_FILE ^
   /D__BUILDV10MODULE ^
   /I"external\mbbs-sdk\inc" ^
   /I"external\mbbs-sdk\inc\msg\v10" ^
   trueip.c

if errorlevel 1 (
    echo.
    echo COMPILE FAILED.
    exit /b 1
)

echo.
echo === Linking TRUEIP.DLL ===

rem /DLL          -- produce a DLL
rem /DEBUG        -- include debug info (references PDB)
rem /OUT          -- output DLL name
rem /DEF          -- module definition file (controls exports and ordinals)
rem /OPT:NOREF    -- keep all referenced symbols (no dead-code elimination)
rem /OPT:NOICF    -- no identical COMDAT folding (preserves distinct fn addrs)
rem /NOLOGO       -- suppress linker banner
rem
rem LIBRARY ORDER:
rem   WGSERVER before GALGSBL (wgserver re-exports some gsbl symbols)
rem   GALTCPIP before GALTNTD (tntincall indirectly uses GALTCPIP sockets)
rem   ws2_32 before advapi32 (no dependency, but conventional order)
rem   msvcrt last (CRT runtime -- resolves _vsnprintf, fopen, etc.)

link /DLL /DEBUG /OUT:TRUEIP.DLL /DEF:TRUEIP_EXP.DEF ^
     /OPT:NOREF /OPT:NOICF /NOLOGO ^
     trueip.obj ^
     "%SDK_LIBS%\WGSERVER_LIB.LIB" ^
     "%SDK_LIBS%\GALGSBL_LIB.LIB" ^
     "%SDK_LIBS%\GALTCPIP_LIB.LIB" ^
     "%SDK_LIBS%\GALTNTD_LIB.LIB" ^
     ws2_32.lib advapi32.lib msvcrt.lib

if errorlevel 1 (
    echo.
    echo LINK FAILED.
    exit /b 1
)

echo.
echo === Exports ===
dumpbin /exports TRUEIP.DLL | findstr "init__trueip"

echo.
echo === BUILD SUCCESS ===
echo Output: TRUEIP.DLL
echo.
echo To install:
echo   1. Copy TRUEIP.DLL    to the BBS runtime directory (alongside GALTCPIP.DLL)
echo   2. Copy Dist\TRUEIP.MDF to the BBS runtime directory
echo   3. Copy Dist\TRUEIP.MSG to the BBS runtime directory
echo   4. Run WGSCNF to configure TPORT, REQHDR, TRUSTIP, MAXRATE
echo   5. Configure your reverse proxy to forward port TPORT with PROXY Protocol v1

endlocal
