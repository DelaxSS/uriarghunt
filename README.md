# uriarghunt

`uriarghunt` is a read-only Windows CLI that audits custom URI protocol handlers under `HKCU` and `HKLM\Software\Classes` without admin privileges. It passes harmless canary probes through Win32 `shell32.dll!CommandLineToArgvW`, checks target PE binaries and Electron Fuses v1 flags, and classifies reachability against live browser escaping and local `ShellExecute` behavior.

## Build

Requires Windows and Go 1.27+ (matching `go.mod`).

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
uriarghunt v0.2.1 - Windows URI Protocol Handler Audit
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

## Measurement Setup

Browser escaping rules were measured on Windows 11 across Chrome 157, Edge 157, Opera GX 139, and Firefox 160.0.1 using a temporary `HKCU\Software\Classes` test scheme pointed at a small helper binary that logged `kernel32.dll!GetCommandLineW()`. Test URIs were triggered from local HTML anchor links for each browser and directly via Windows `ShellExecute` for the local baseline, then cleaned up after capture.

## Browser Escape Measurements & Limitations

- Chrome 157, Edge 157, Opera GX 139, and Firefox 160.0.1 all percent-encode space (`%20`), `"` (`%22`), `\` (`%5C`, including trailing `\`), `<` (`%3C`), `>` (`%3E`), `` ` `` (`%60`), `|` (`%7C`), and `^` (`%5E`) in non-special scheme paths/queries while passing `&` raw.
- Chromium encodes `%` as `%25` and rejects `"`, space, or `\` in the authority; Firefox 160.0.1 passes `%` raw (`a%Zb` stays `a%Zb`), rejects space and `\` in the authority, and encodes authority `"` as `%22`.
- Local Windows `ShellExecute` passes all of these raw, allowing both quote splits and trailing-backslash quote breaks; in all four browsers, `quote_split`, `space_split`, and trailing-`\` breaks are blocked while raw `&` (and raw `%` in Firefox) reaches unquoted `cmd.exe`/`.bat`/`.cmd` handlers.
- `FUSES` reflects binary-level Electron Fuses v1 flags only; custom application `argv` parsing and `DelegateExecute` COM handlers require separate inspection.

## Responsible Disclosure

`uriarghunt` is read-only and uses harmless canary probes (`--uriarghunt-canary`) for local auditing. Report confirmed third-party issues through the vendor's security channel with a minimal PoC and recommend placing `--` before `"%1"`.
