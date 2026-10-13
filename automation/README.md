# LCS JIT + SQL automation

## Fresh-machine start (Windows x64)

1. Copy/extract the whole project to a **writable local folder**. Keep this layout:

   ```text
   run.ps1
   config.yaml
   sql_scripts/        Your trusted .sql files
   automation/        Code, setup, documentation, tests and local runtime
   ```

2. Edit the **root `config.yaml`**. Only four fields are needed:

   | Field | What to enter |
   |---|---|
   | `ENVIRONMENT_URL` | Complete HTTPS **LCS environment-details** URL from your sandbox, including `EnvironmentId`. Not the application's URL or project overview. |
   | `ACCESS_REASON` | Exact LCS **Reason for access** option. This determines permissions. |
   | `ACCESS_DETAILS` | Approved justification for the Request access block. |
   | `FIREWALL_RULE_NAME` | Temporary rule name: 1–64 letters/digits/underscores/hyphens, beginning with a letter or digit. Never overwrites an existing conflicting rule. |

   Supported reasons:
   - `AX troubleshooting (read-only to AX)` — read-only AX
   - `MR troubleshooting (read-only to MR)` — read-only MR
   - `Performance tuning for AX (write to AX)` — read/write AX
   - `Troubleshooting and tuning entity store (write to AXDW)` — read/write AXDW

   Current config retains the previously approved **write-to-AX** reason. The two sample scripts are SELECT-only, but that does not make the granted account read-only. Choose the least privilege your approved scripts need. Scripts must target the database associated with the chosen reason.

3. Put trusted UTF-8 `.sql` files directly in **`sql_scripts/`**. Every top-level `.sql` file runs alphabetically; subfolders are not scanned. Remove/move samples from this folder if you do not want them executed. Never run unreviewed writes against application databases.

4. Open PowerShell in the root folder and run:

   ```powershell
   ./run.ps1
   ```

   First-time setup automatically:
   - Finds a supported **x64 Python 3.10–3.13**, or installs verified Python **3.13.16** under `automation/runtime/python/` without changing PATH.
   - Creates an isolated `automation/.venv/` and installs Python requirements.
   - Uses an installed Microsoft SQL ODBC Driver **18 or 17** (prefers 18), or downloads/verifies and installs **Driver 18.7**. Windows may ask for **administrator/UAC approval**. Driver 18.7 does not require a separately installed Visual C++ Redistributable.
   - Installs and launch-tests project-local Playwright Chromium under `automation/browsers/`.
   - Validates configuration and SQL batch syntax before LCS access changes.

   Then it reuses a valid saved login or opens a browser. **Sign in, complete MFA, wait for the configured environment page, then press Enter in PowerShell.** It proceeds with temporary firewall access → JIT credentials → SQL execution → owned-rule cleanup.

5. Read the terminal result and **`automation/logs/<UTC timestamp>/report.json`**. SQL success requires `status: success`, `sql_execution.scripts_failed: 0`, and the expected `scripts_executed` count. Credentials appearing in LCS do not prove SQL executed.

For a fresh copy, copy root `run.ps1`, `config.yaml`, `sql_scripts/`, and the source files in `automation/`. **Exclude** `.venv/`, `.venv.backup-*/`, `.auth/`, `browsers/`, `runtime/`, `logs/`, caches and `.launcher.lock`. A copied unusable virtual environment is preserved as a `.venv.backup-*` and rebuilt. Always log in locally under the Windows identity that will run the tool; DPAPI authentication is not portable to unrelated machines/users. No username/password, Python path, driver name, project ID, environment heading, selectors or authentication key is required in the normal config.

## Modes

```powershell
./run.ps1                     # Setup if needed; reuse login or prompt; run visibly
./run.ps1 -ValidateOnly       # Setup + local checks only; no LCS grant or SQL execution
./run.ps1 -LaunchOnly         # Setup + fresh login only; no grant or SQL execution
./run.ps1 -ForceInteractive   # Fresh login, then full visible workflow
./run.ps1 -Headless           # Setup + unattended workflow; needs valid saved login
./run.ps1 -Config my.yaml     # Alternate YAML, relative to launcher directory
```

The root launcher works from another current directory too, using its own directory for the default config. Relative paths in an alternate YAML resolve from **that YAML's directory**. The compatibility wrapper now lives inside `automation/`: `automation/run.cmd --validate-only` (also supports `--config`, `--headless`, `--launch-only`, `--force-interactive`).

## What setup cannot bypass

- Automatic setup targets **Windows x64**, Windows 10 1809 / Server 2019 or newer (including Windows 11). It does not provide macOS/Linux/ARM64/32-bit installation. Use a supported, maintained Windows release.
- First-time downloads require Internet access to python.org, PyPI/package downloads, Microsoft's ODBC download endpoints and Playwright browser download endpoints. Corporate proxies, endpoint security, disk space and administrator restrictions can block installation. Setup stops with an error instead of proceeding with missing dependencies. Review installer logs in `automation/runtime/installers/`. A required restart stops the run; restart and rerun.
- If PowerShell policy blocks the script, use your organization's approved script signing/execution policy. The launcher does not disable execution policy, TLS certificate validation, Windows Firewall, network policy or Conditional Access.
- MFA and UAC require human approval when requested. The launcher cannot bypass them.
- The SQL host must be reachable: Azure SQL gateway **TCP 1433**, plus regional endpoints on **TCP 11000–11999** if the connection uses Redirect. An LCS inbound rule cannot repair blocked outbound VPN/firewall/routing. HTTPS and SQL egress IPs can differ behind a proxy.
- **Previous live test: SQL connection failed; no scripts executed.** Browser grant/extraction/cleanup passed. See [LIVE_TEST_RESULTS.md](LIVE_TEST_RESULTS.md) for dated evidence. The simplified setup does not resolve that external network blocker.
- This adapter targets **LCS-managed sandbox environments**, not PPAC-managed environments. Different/changed LCS UI may need internal selector recalibration; an environment URL alone cannot guarantee all tenants share the same DOM.

## Internal defaults and advanced profiles

`automation/defaults.yaml` holds selectors and safe execution defaults. The launcher derives the numeric project ID and environment GUID from the URL, verifies the URL before discovering the environment heading, derives permission audit metadata from the reason, auto-detects the ODBC driver, and creates environment-specific encrypted login paths under `automation/.auth/`. Cleanup is on; stop-on-error is on. Normal users should not edit internal defaults.

For specialist changes use `automation/config.advanced.yaml` as a reference, then `./run.ps1 -Config automation/config.advanced.yaml`. It explicitly preserves the older calibrated profile and its Driver 17 selection; adjust it to your host if used. Uppercase environment variables override corresponding YAML fields, so remove old overrides when changing environments. Unknown configuration/selector keys and inconsistent known reason/permission pairs are rejected.

Required selector calibration uses **sanitized** environment/accounts/dialog HTML only. Never share live tokens, credentials, page dumps or network captures. `accounts` must enclose every credential display; screenshots mask that container before encoding. Missing/ambiguous cells and unknown expiry formats fail closed. UTC is forced for the calibrated LCS expiry display. The four known reasons support inferred permissions; a new reason requires an advanced profile with an explicit `ACCESS_LEVEL` plus verified UI behavior. That field is audit metadata, not enforcement: LCS reason determines the actual permissions.

## Safety and execution behavior

- SQL passwords remain in process memory; they are not stored in config, environment variables or reports. Authentication storage (cookies/local storage/IndexedDB) is Fernet-encrypted; its local key is protected by Windows DPAPI. Protect `automation/.auth/` and logs with Windows ACLs. OS permissions, page files, process memory and crash dumps still require protection.
- Screenshots mask credentials **before** encoding/writing; unknown/login pages are fully masked. Never enable traces, HAR, video, Playwright debug/API output or network captures. Raw browser/ODBC exceptions are suppressed. Reports redact exact known passwords but are not a general DLP system; SQL results may contain sensitive business data.
- Firewall Service stays at LCS's automatic **AzureSQL** value. A valid existing matching IP/service rule is reused but never claimed or deleted. Expired rules are not reused. Conflicting names fail without modifying that rule. Cleanup deletes only the exact name/IP/service rule created by the run and checks absence in a refreshed grid. Failure to confirm cleanup returns failure even if SQL succeeded.
- Cleanup removes firewall access, **not SQL credential validity**. SQL credentials may remain valid until expiry. A shared egress IP can affect other sessions; use an approved dedicated host/IP. Termination/power loss cannot guarantee cleanup; `owned_rule.json` records exact rule identity for recovery.
- Effective expiry is the earliest of displayed credential expiry, request + 8 hours and firewall expiry. Expiry is checked before connection, batches, result fetches and commit; an in-flight synchronous query cannot be interrupted exactly at expiry. Queries have an ODBC timeout.
- Scripts are UTF-8/UTF-8 BOM plain T-SQL, one transaction per script with all result sets drained before commit and `SELECT 1` preflight. Standalone `GO` (optional trailing `--` comment) splits batches, respecting strings/identifiers/nested comments. `GO n`, sqlcmd directives and substitution are unsupported. Scripts must not issue their own COMMIT/ROLLBACK, change databases/connection settings or use statements incompatible with transactions; these defeat rollback guarantees.
- Successful earlier scripts remain committed after a later failure; no automatic replay of data-changing scripts. Normal config stops after a failed script. Advanced `CONTINUE_ON_ERROR: true` continues only after successful rollback, not expiry; any failure returns exit 1.
- Result retention defaults to 100 rows **per result set**, not an overall bytes limit. Large cells/many result sets can produce large reports. Use bounded, approved queries.
- The launcher serializes local setup/auth/run; the CLI also locks by project/environment/log directory. These locks do not coordinate other machines, different log directories or manual requests.

The Python CLI emits one JSON object and exits 0 on success / 1 on failure. The launcher also emits setup/progress output and preserves the CLI exit status. A report with `failed_at_step: sql_connection` means no SQL scripts ran. Diagnostics contain static frame/type metadata only, not exception text. Logs and local runtime stay inside `automation/`.

## Developer verification / scheduling

From the project root (Git Bash shown):

```bash
automation/.venv/Scripts/python -m pip install -r automation/requirements-dev.txt
automation/.venv/Scripts/python -m mypy --cache-dir automation/.mypy_cache automation/automation_support.py automation/lcs_jit_automation.py automation/sql_executor.py automation/main.py
automation/.venv/Scripts/python -m pytest automation/tests
```

Tests use routed LCS-like browser fixtures and fake ODBC connections; fixture success is not live SQL verification. Installer orchestration can be tested without reinstalling a machine-wide driver. Real fresh-copy setup and its limitations are recorded in [LIVE_TEST_RESULTS.md](LIVE_TEST_RESULTS.md).

For Task Scheduler, use Windows PowerShell with `-NoLogo -NoProfile -File C:/absolute/project/run.ps1 -Headless`. Bootstrap first on the same trusted host/identity, allow required downloads during initial setup, and prevent overlap. No scheduled task or deployment is created by this repository. Direct Python CLI use must set `PLAYWRIGHT_BROWSERS_PATH` to the absolute `automation/browsers/` path if using launcher-installed browsers.

Sources: [Microsoft JIT access](https://learn.microsoft.com/en-us/dynamics365/fin-ops-core/dev-itpro/database/database-just-in-time-jit-access), [ODBC downloads/prerequisites](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server), [Python 3.13.16](https://www.python.org/downloads/release/python-31316/), [Playwright authentication](https://playwright.dev/python/docs/auth).
