# uriarghunt

`uriarghunt` audits custom Windows URI protocol handlers (`HKCU`/`HKLM\Software\Classes`) without administrator privileges. It invokes Win32 `shell32.dll!CommandLineToArgvW` directly to test harmless canary probes for argument splitting, fingerprints target PE binaries (Electron, CEF, Chromium, Node, Java, Shell/LOLBin), and filters results against current Chrome/Edge 130+ and Firefox URI escaping rules.

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
.\uriarghunt.exe inspect openvpn-connect   # inspect argv, PE, and escape details for one scheme
```

## Example Output

```text
uriarghunt v0.1.0 — Windows URI Protocol Handler Audit
Schemes : 250 total (HKCU=136, HKLM=114, shadows=6) | 72 with command (3rd-party=31, builtin=41, --=6, dangling=1)
3rdParty: TIER 3=8  TIER 2=10  TIER 1=7
Filter  : hiding 41 builtin OS/browser schemes (use --include-builtin), min-tier=0

TIER    SCHEME                  SCOPE      HIVE   PLACEHOLDER  SPLIT(A/B)  FLAG     RUNTIME   REACHABILITY           TARGET_EXE
------  ------                  -----      ----   -----------  ----------  ----     -------   ------------           ----------
TIER 3  flywheel-local          3rd-party  HKCU   "%1"         +2/-        YES      electron  local-split+dash-cand  Local.exe
TIER 3  GeForceNOW              3rd-party  HKCU   "%1"         +2/-        YES      cef       local-split+dash-cand  GeForceNOW.exe
TIER 3  jnlp                    3rd-party  HKLM   "%1"         +2/-        YES      java      local-split+dash-cand  jp2launcher.exe
TIER 3  openvpn-connect         3rd-party  HKCU   "%1"         +2/-        YES      electron  local-split+dash-cand  OpenVPNConnect.exe
TIER 2  riotclient              3rd-party  HKLM   "%1"         +2/-        YES      electron  local-only             RiotClientServices.exe
TIER 2  spotify                 3rd-party  HKCU   "%1"         +2/-        YES      cef       local-only             Spotify.exe
TIER 1  com.cloudflare.warp     3rd-party  HKCU*  "%1"         +2/-        YES      native    local-split+dash-cand  Cloudflare WARP.exe
TIER 1  com.epicgames.launcher  3rd-party  HKLM   %1 (UNQ)     -/+1        YES      native    local-split+dash-cand  EpicGamesLauncher.exe
INFO    csgo                    3rd-party  HKCU   "%1"         +2/-        YES      dangling  local-split+dash-cand  cs2.exe
INFO    Discord                 3rd-party  HKCU   "%1"         +2/-        after--  electron  mitigated              Discord.exe
INFO    vscode                  3rd-party  HKCU   "%1"         +2/-        after--  electron  mitigated              Code.exe
```

## Tier Definitions

- **INFO (0):** Dangling target binary, `--`-guarded template, or no detected split.
- **TIER 1 (1):** Deterministic `CommandLineToArgvW` split, unquoted executable path with spaces, or post-`--` positional corruption.
- **TIER 2 (2):** Tier 1 argument split on a high-risk runtime (`electron`, `cef`, `chromium`, `node`, `shell`, `java`, `lolbin`).
- **TIER 3 (3):** Tier 2 plus a vector that passes browser percent-encoding (pre-`--` trailing backslash quote break or missing `--` dash candidate).

## Limitations

- `TIER 3` is a prioritization signal, not proof of exploitability; application-side `argv` filtering and Electron fuses (`app.asar`) must be checked manually.
- Chrome/Edge 130+ and Firefox percent-encode spaces (`%20`) and quotes (`%22`) in non-special schemes, so `local-only` and raw quote/space splits apply to non-browser triggers (`.lnk`, `.url`, desktop apps, raw `ShellExecute`).
- Handlers backed exclusively by `DelegateExecute` COM servers have no command template to evaluate statically.

## Responsible Disclosure

`uriarghunt` is read-only and emits only harmless canary probes (`--uriarghunt-canary`) for defensive auditing. If you confirm a real argument injection issue in a third-party application, report it through the vendor's security channel with a minimal non-destructive PoC and recommend adding `--` before `"%1"`.
