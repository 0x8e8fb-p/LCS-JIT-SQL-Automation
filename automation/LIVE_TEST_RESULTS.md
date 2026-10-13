# Live verification — LCS sandbox (2026-10-08)

## Current outcome

**Browser automation verified live; SQL execution remains blocked by connectivity.**

Tested the actual default interface: **`./run.ps1`**, using **`config.yaml`**, a visible Playwright Chromium browser, and existing encrypted authentication. The configured reason remains **Performance tuning for AX (write to AX)** and details **test access**, as explicitly confirmed by the user. Firewall name is **test**; Service is left at the automatic **AzureSQL** value. Only the two SELECT-only samples were approved for this test; neither executed because SQL did not connect.

| Check | Actual result |
|---|---|
| Default config and launcher path handling | Pass — config.yaml is the default; PowerShell and batch wrappers tested from another working directory |
| Configuration/scripts/runtime preflight | Pass — two UTF-8 SQL scripts validated, configured Driver 17 installed, Chromium available |
| Saved authentication reuse | Pass — default launcher checked the existing session and skipped unnecessary interactive bootstrap |
| Environment guard | Pass — exact heading plus project/environment URL verified |
| Live dropdown options | Pass — exact options inspected online (listed below) |
| Maintain > Enable access | Pass — real menu opens the Modify-firewall-rules grid |
| Create test firewall rule | Pass — entered name/IP, left Service untouched, confirmed in a freshly loaded grid |
| Reason/details/request access | Pass — configured dropdown option selected, details entered and blurred, request submitted once |
| Refresh/extract credentials | Pass — changed credential row matched reason/details; server/database, username, revealed password, and UTC expiry extracted into memory |
| SQL connection/preflight | **Failed** — both ODBC connection attempts failed; no SQL script execution |
| Automatic cleanup after SQL failure | Pass — exact owned rule selected/deleted; fresh grid confirmed absence |
| Independent final-state inspection | Pass — a separate browser session reopened the real grid and found **zero firewall rules** |
| Process exit/report | Pass — launcher exit **1**, report status failure at sql_connection, cleanup success |
| Typechecking and regression tests | Pass — mypy clean; **43 tests passed**, including launcher subprocesses and real-browser local fixtures |

Automation pipeline time: **284.656 seconds** (about 4 minutes 45 seconds), including the failed connection attempts and successful cleanup. This is **not** a measured successful SQL end-to-end run and does not establish a completion-time guarantee. Launcher preflight/authentication checking adds time outside that pipeline measurement.

Local evidence (ignored by Git):

- `logs/launcher_final_2026-10-08.log`
- `logs/launcher_final_2026-10-08.exit`
- `logs/2026-10-08_06-32-32_290413/report.json`
- Masked stage screenshots and the non-secret `owned_rule.json` recovery record in the same run directory.

No passwords, decrypted browser state, traces, HAR files, or network payload captures were written. Pixel verification covers pre-encoding masking in the browser fixture; live screenshot inspection also confirmed the large black mask. Screenshots/results still require protected local storage.

## Options confirmed on the actual LCS page

- AX troubleshooting (read-only to AX)
- MR troubleshooting (read-only to MR)
- **Performance tuning for AX (write to AX)** — configured/user-approved
- Troubleshooting and tuning entity store (write to AXDW)

`ACCESS_LEVEL` is consistent with this reason (`read_write`). The sample scripts being SELECT-only does **not** make the granted SQL account read-only.

## Live bug discovered and repaired

The first retest created the rule but failed to click the parent dialog's Close button; cleanup in that same stale page also failed. Online inspection found an invisible **popupShadow/modalBackground** layer left after the add dialog disappeared. The previous JavaScript-click fallback concealed this condition by bypassing browser actionability checks.

The created rule was recovered using its exact recorded name/IP/service and deleted; absence was verified. The adapter now waits for LCS processing, reloads the verified environment, and reopens the grid to read server state. Cleanup uses the same refresh strategy. It does not force clicks, remove overlay nodes, or resubmit grants. A browser regression fixture deliberately reproduces the stale modal layer. The subsequent default-launcher run passed all browser stages and automatic cleanup.

Other repairs: expired matching rules are no longer reused; unsupported/unreadable/empty SQL is rejected before access changes; environment checks are exact; unknown configuration keys/inconsistent known reasons fail validation; a local OS lock prevents overlapping runs sharing an environment/log directory; the batch wrapper delegates to PowerShell and retains its launcher path before parsing arguments.

## Remaining connectivity blocker

A fresh independent test on 2026-10-08 found:

- Azure SQL hostname DNS resolution succeeds.
- TCP **1433** to the sandbox's Azure SQL server times out (4-second diagnostic probe).
- An additional **11000** probe to the same hostname also times out. This alone does not test all redirected cluster endpoints or the complete redirect range.
- The automation's ODBC connection/preflight failed twice. SQL login, TLS negotiation, SQL correctness, and live transactional behavior therefore remain unverified.

The missing TCP 1433 reachability is an external network/connectivity blocker; its precise filtering/routing cause has not been established. An LCS firewall rule cannot repair the host's outbound path. No host/network policy, Azure connection policy, or other system setting was changed.

Microsoft documents gateway TCP **1433**, plus outbound TCP **11000–11999** to regional Azure SQL endpoints when **Redirect** is used. **Proxy** uses gateway 1433. Have the network path approved or run on an approved host with the required connectivity, then repeat `./run.ps1`. On a different Windows host/identity, bootstrap there; DPAPI-protected state cannot simply be copied to an unrelated identity.

## Environment state after testing

- No SQL scripts ran; no application data/schema changes were performed.
- All test-created firewall rules were removed, including recovery from the first retest; an independent final inspection found the grid empty.
- LCS-created credential rows may remain valid until their displayed expiry. Firewall cleanup is **not** SQL credential revocation.
- Login/MFA remains interactive if Entra stops accepting the saved session. No MFA bypass is implemented or promised.
- Power loss/process termination cannot guarantee firewall cleanup; `owned_rule.json` supports exact manual recovery.

## References checked online

- [Microsoft: Enable just-in-time database access](https://learn.microsoft.com/en-us/dynamics365/fin-ops-core/dev-itpro/database/database-just-in-time-jit-access) — environment details > Maintain > Enable access; request credentials in Database Accounts; refresh; server/database connection semantics; eight-hour firewall lifetime.
- [Microsoft: Azure SQL connectivity architecture](https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture?view=azuresql) — gateway/Redirect/Proxy port requirements.

Previous testing on 2026-10-07 reached the same SQL transport blocker. The current results above supersede the earlier selector-only/local test count and verify the repaired workflow through the requested launcher.
