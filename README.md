# uriarghunt

`uriarghunt` audits Windows URI protocol handlers (`HKCU`/`HKLM\Software\Classes`) without administrator privileges. It invokes Win32 `shell32.dll!CommandLineToArgvW` directly to test harmless canary probes for argument splitting, inspects target PE binaries and Electron Fuses v1 wires, and evaluates reachability against empirically measured Chromium escaping and local Windows `ShellExecute` behavior.

## Build

Requires Windows and Go 1.22+.

```powershell
go test ./...
go build -trimpath -ldflags="-s -w" -o uriarghunt.exe ./cmd/uriarghunt
```

## Usage

```powershell
.\uriarghunt.exe                           # audit third-party handlers (TIER 3 -> INFO)
.\uriarghunt.exe scan --min-tier 2         # show only TIER 2 and TIER 3 findings
.\uriarghunt.exe scan --include-builtin    # include built-in Windows/browser schemes
.\uriarghunt.exe scan --min-tier 2 --json  # emit JSON report
.\uriarghunt.exe inspect openvpn-connect   # inspect argv, PE, fuses, and escape details
```

## Example Output

```text
uriarghunt v0.2.0 — Windows URI Protocol Handler Audit
Schemes : 250 total (HKCU=136, HKLM=114, shadows=6) | 72 with command (3rd-party=31, builtin=41, --=6, dangling=1)
3rdParty: TIER 3=0  TIER 2=18  TIER 1=7
Filter  : hiding 41 builtin OS/browser schemes (use --include-builtin), min-tier=0

TIER    SCHEME                  SCOPE      HIVE   PLACEHOLDER  SPLIT(A/B)  FLAG     RUNTIME   FUSES         REACHABILITY          TARGET_EXE
------  ------                  -----      ----   -----------  ----------  ----     -------   -----         ------------          ----------
TIER 2  flywheel-local          3rd-party  HKCU   "%1"         +2/-        YES      electron  inspect+node  local-only,missing--  Local.exe
TIER 2  GeForceNOW              3rd-party  HKCU   "%1"         +2/-        YES      cef       -             local-only,missing--  GeForceNOW.exe
TIER 2  jnlp                    3rd-party  HKLM   "%1"         +2/-        YES      java      -             local-only,missing--  jp2launcher.exe
TIER 2  openvpn-connect         3rd-party  HKCU   "%1"         +2/-        YES      electron  hardened      local-only,missing--  OpenVPNConnect.exe
TIER 2  spotify                 3rd-party  HKCU   "%1"         +2/-        YES      cef       -             local-only            Spotify.exe
TIER 1  com.cloudflare.warp     3rd-party  HKCU*  "%1"         +2/-        YES      native    -             local-only,missing--  Cloudflare WARP.exe
TIER 1  com.epicgames.launcher  3rd-party  HKLM   %1 (UNQ)     -/+1        YES      native    -             local-only,missing--  EpicGamesLauncher.exe
INFO    csgo                    3rd-party  HKCU   "%1"         +2/-        YES      dangling  -             local-only,missing--  cs2.exe
INFO    Discord                 3rd-party  HKCU   "%1"         +2/-        after--  electron  hardened      mitigated             Discord.exe
INFO    vscode                  3rd-party  HKCU   "%1"         +2/-        after--  electron  inspect+node  mitigated             Code.exe
```

Column notes: `SPLIT(A/B)` shows `argc` delta for `quote_split` / `space_split` probes; `HIVE*` means `HKCU` shadows `HKLM`; `FUSES` decodes the Electron Fuses v1 sentinel (`hardened` = `RunAsNode` and `EnableNodeCliInspectArguments` disabled).

## Tier Definitions

- **INFO (0):** Dangling target binary, `--`-guarded template with quoted exe path, or no detected split.
- **TIER 1 (1):** Deterministic local `CommandLineToArgvW` split, unquoted executable path with spaces, or local post-`--` positional corruption.
- **TIER 2 (2):** Tier 1 argument split on a high-risk runtime (`electron`, `cef`, `chromium`, `node`, `shell`, `java`, `lolbin`), blocked by browser encoding (`local-only`, with `missing--` and Electron Fuses noted).
- **TIER 3 (3):** Verified browser-surviving vector (unquoted `cmd.exe`/`.bat`/`.cmd` handler receiving raw `&`, or a `CommandLineToArgvW` split that survives browser percent-encoding).

## Browser Escape Measurements & Limitations

- Live `GetCommandLineW()` measurements on Windows 11 confirmed that Chrome 157, Edge 157, and Opera GX 139 percent-encode space (`%20`), `"` (`%22`), `\` (`%5C`), `<` (`%3C`), `>` (`%3E`), `` ` `` (`%60`), `|` (`%7C`), `^` (`%5E`), and `%` (`%25`) in non-special schemes (and reject `"`, space, or `\` in authority), while passing `&` raw. Local Windows `ShellExecute` passes all of these raw, allowing both quote splits and trailing-backslash quote breaks.
- Firefox behavior is modeled from standard WHATWG non-special escaping and has not yet been empirically measured on this host.
- `FUSES` reflects binary-level Electron Fuses v1 flags only; custom application `argv` parsing and `DelegateExecute` COM handlers require separate inspection.

## Responsible Disclosure

`uriarghunt` is read-only and uses harmless canary probes (`--uriarghunt-canary`) for local defensive auditing. If you confirm a real argument injection issue in a third-party application, report it through the vendor's security channel with a minimal non-destructive PoC and recommend adding `--` before `"%1"` (plus disabling unused Electron fuses).
