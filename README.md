# LCS JIT SQL Automation

Run local SQL scripts against a Dynamics 365 Finance and Operations sandbox using temporary database access from Lifecycle Services (LCS).

The launcher prepares a project-local runtime, opens a browser when sign-in is needed, requests JIT credentials, executes the scripts, and removes the firewall rule it created. Later runs reuse the saved login while it remains valid.

This project supports **LCS-managed sandbox environments on Windows x64**. It does not support Power Platform admin center (PPAC) access flows. Different LCS interfaces may require changes to the browser adapter.

## Requirements

- Windows x64: Windows 10 version 1809, Windows 11, or Windows Server 2019 or newer.
- A local, writable folder for the extracted project. Not a network drive; avoid OneDrive-synced folders and very long paths. A short folder such as `C:\LCSJIT` is the most reliable.
- An LCS account authorized to manage database access for the target sandbox.
- Administrator approval (a Windows UAC prompt) if the Microsoft ODBC driver for SQL Server must be installed.
- Network access. The first run downloads only what is missing:

| Host | Used for |
|---|---|
| `api.nuget.org` | Python 3.13.16 (official nuget.org package, about 15 MB) |
| `pypi.org`, `files.pythonhosted.org` | Pinned Python packages (or the index set in `PIP_INDEX_URL` / `pip.ini`) |
| `go.microsoft.com`, `download.microsoft.com` | Microsoft ODBC Driver 18 for SQL Server, only if neither Driver 18 nor 17 is installed |
| `cdn.playwright.dev`, `storage.googleapis.com` | Chromium for the browser automation (or the host set in `PLAYWRIGHT_DOWNLOAD_HOST`) |
| `lcs.dynamics.com` (or your regional LCS host), `login.microsoftonline.com` and your organization's sign-in pages | LCS and Microsoft sign-in |
| `api.ipify.org` | Public IPv4 detection for the firewall rule, unless `PUBLIC_IP` is set |
| Your Azure SQL server, TCP 1433 (and 11000–11999 for the Redirect policy) | The SQL scripts |

You do **not** need Python, a browser or administrator rights beforehand. The launcher cannot bypass MFA, Windows UAC, Group Policy, endpoint security or network restrictions. When one of them blocks a step, the launcher names it. The exception is an execution policy enforced by Group Policy, which stops PowerShell before the launcher starts (see [Troubleshooting](#troubleshooting)).

## Quick start

### 1. Download and extract the project

Use **Code → Download ZIP** on GitHub and extract the entire archive, or clone it:

```powershell
git clone https://github.com/0x8e8fb-p/LCS-JIT-SQL-Automation.git
cd LCS-JIT-SQL-Automation
```

Open PowerShell or Windows Terminal in the folder that contains `run.cmd`. Do not run it from inside the ZIP viewer.

### 2. Create your configuration

```powershell
.\run.cmd
```

`run.cmd` starts 64-bit Windows PowerShell with `-ExecutionPolicy Bypass` for that one process, so it works on machines whose default policy blocks downloaded scripts. The machine policy is not changed, and Group Policy still applies. The launcher also removes the download mark from the project's own launcher scripts (`run.ps1`, `run.cmd`, `automation\setup.ps1` and `automation\run.cmd`), so `./run.ps1` works afterwards where the `RemoteSigned` policy applies.

On a fresh download, the launcher creates `config.yaml` from the bundled template and stops so you can edit it. **This first invocation returns exit code 1 by design.** It does not install anything, request access, or execute SQL. An existing `config.yaml` is never overwritten.

Open `config.yaml` in a text editor and save it as UTF-8:

```yaml
ENVIRONMENT_URL: "https://lcs.dynamics.com/V2/EnvironmentDetailsV3New/123456?EnvironmentId=11111111-2222-4333-8444-555555555555"
ACCESS_REASON: "AX troubleshooting (read-only to AX)"
ACCESS_DETAILS: "Approved sandbox database validation"
FIREWALL_RULE_NAME: ""
```

The URL above is an example. Replace it with your sandbox's complete **LCS environment-details URL**, copied from the browser address bar. See [Configuration](#configuration) for the other fields.

Your personal `config.yaml` is excluded from Git and never replaced by updates.

### 3. Review the SQL scripts

Place the scripts you intend to execute directly in `sql_scripts/`. The repository includes two non-mutating examples:

| File | Purpose |
|---|---|
| `01_connectivity.sql` | Returns the database name, server UTC time, and a connectivity result. |
| `02_read_only_validation.sql` | Returns up to ten table names from `INFORMATION_SCHEMA.TABLES`, subject to the account's permissions. |

**Every top-level `.sql` file in this folder is included in the run.** Remove or move any script you do not want executed. Use only reviewed scripts and obtain the required approval before making database changes.

### 4. Prepare and validate

```powershell
.\run.cmd -ValidateOnly
```

This checks the computer, installs what is missing, and validates the configuration, script encoding and batch syntax, ODBC driver and browser. It does not sign in to LCS, grant access, or execute SQL. The output also shows the firewall rule name this computer will use.

A successful validation does not prove that the SQL server is reachable, that every T-SQL statement is valid, or that the account has permission to execute it.

### 5. Run the workflow

```powershell
.\run.cmd
```

If no valid saved login exists, the launcher says why, then:

1. Sign in in the browser window it opens.
2. Complete MFA if requested.
3. Wait for the configured environment-details page to load.
4. Return to the terminal and press **Enter**.

The launcher then manages firewall access, requests credentials, executes the scripts, and performs cleanup. Keep the terminal and browser open until the run finishes.

### 6. Check the result

Read the terminal output and the report at `automation/logs/<UTC timestamp>/report.json`. Confirm the overall status, the number of successful scripts and the cleanup status. Seeing credentials in LCS is not evidence that SQL executed.

## Configuration

| Field | Value |
|---|---|
| `ENVIRONMENT_URL` | The complete HTTPS LCS environment-details URL, including its `EnvironmentId` query parameter. Do not use the application URL or the LCS project overview. |
| `ACCESS_REASON` | The exact **Reason for access** label shown in LCS. It determines the granted database permissions. |
| `ACCESS_DETAILS` | A non-empty justification entered into the LCS Request access block. Follow your organization's approval policy. |
| `FIREWALL_RULE_NAME` | Leave blank to use a name for this computer and Windows user: `lcsjit-` plus 8 hexadecimal characters derived from both, so computers sharing an environment use different names. Or set 1–64 letters, digits, underscores or hyphens, starting with a letter or digit. An existing rule is never overwritten. |
| `PUBLIC_IP` (optional) | The public IPv4 address your SQL traffic leaves from. Set it only when automatic detection is blocked or picks the wrong address (proxy, VPN, split tunnel). When Azure SQL refuses the address, the error shows the exact line to add. |

Supported reason labels:

| LCS reason | Requested access |
|---|---|
| `AX troubleshooting (read-only to AX)` | Read-only access to AX |
| `MR troubleshooting (read-only to MR)` | Read-only access to MR |
| `Performance tuning for AX (write to AX)` | Write access to AX |
| `Troubleshooting and tuning entity store (write to AXDW)` | Write access to AXDW |

Choose the least privilege required by your scripts. A SELECT-only script does not make a write-enabled account read-only.

URLs must use `https://<LCS host>/V2/EnvironmentDetailsV3New/<project ID>` with the lowercase environment GUID and no fragment. Supported LCS hosts: `lcs.dynamics.com`, `eu.lcs.dynamics.com`, `fr.lcs.dynamics.com`, `sa.lcs.dynamics.com`, `uae.lcs.dynamics.com`, `ch.lcs.dynamics.com` and `no.lcs.dynamics.com`. UTF-8 with or without BOM and surrounding whitespace are accepted.

Problems with the settings are listed together in one numbered message: unknown keys, the wrong part of the URL, unsupported reasons, empty fields and conflicting environment variables. File problems (a missing file, UTF-16 or ANSI encoding, invalid YAML with its line and column, a duplicate key) are reported first, on their own. Messages name the fields, not their values; only a URL's host name is shown.

With `config.yaml`, environment variables can override the four main fields. Any other setting found in the environment, such as `LOGS_PATH`, `DISABLE_ACCESS_AFTER` or `PUBLIC_IP`, is refused with its name and a `Remove-Item Env:NAME` hint instead of silently changing the run. Windows matches variable names in any letter case. Put `PUBLIC_IP` in `config.yaml`.

### Advanced profiles

Most users should use `config.yaml`. For custom script locations, timeouts or selector changes, copy [the advanced reference profile](automation/config.advanced.yaml), for example to `automation/my-profile.local.yaml`. Replace its example URL and the `REPLACE_` values; a profile that still contains a `REPLACE_` value is rejected. Then run:

```powershell
.\run.cmd -Config "automation/my-profile.local.yaml"
```

Files named `*.local.yaml` are ignored by Git. Relative paths inside a profile resolve from the profile's folder. A relative `-Config` path resolves from the project folder for both `run.cmd`/`run.ps1` and `automation\run.cmd --config`. The driver is chosen automatically (Driver 18, then 17) unless a profile sets `SQL_ODBC_DRIVER`. Unlike `config.yaml`, an advanced profile accepts every top-level setting from an environment variable of the same name.

## Launcher options

| Command | Behavior |
|---|---|
| `.\run.cmd` | Prepare prerequisites, reuse a valid login or prompt for sign-in, then run with a visible browser. |
| `.\run.cmd -ValidateOnly` | Prepare prerequisites and perform local checks only. |
| `.\run.cmd -LaunchOnly` | Prepare prerequisites, validate, and save a fresh login. Do not grant access or run SQL. |
| `.\run.cmd -ForceInteractive` | Require a fresh interactive login, then run the complete workflow. |
| `.\run.cmd -Headless` | Run without a visible browser using the saved login. It does not prompt for sign-in. |
| `.\run.cmd -Config "my-profile.local.yaml"` | Use an alternate configuration. |

`./run.ps1` accepts the same parameters when your execution policy allows it. Use the mode switches separately; `-Config` can be combined with a mode. The compatibility wrapper `automation\run.cmd` takes `--validate-only`, `--headless`, `--launch-only`, `--force-interactive` and `--config <path>`.

## First-time setup and repeat runs

The launcher keeps everything it installs inside `automation/`. Outside that folder, only the ODBC driver is installed for the whole computer; temporary files go to `%TEMP%`, and pip keeps its usual per-user cache.

1. **Preflight.** All local blockers are reported together before anything is downloaded: unsupported Windows or 32-bit PowerShell, the PowerShell ISE, network drives, `[ ]` or backticks in the path, an unwritable folder, low disk space, and paths too long without Win32 long paths. OneDrive and Controlled Folder Access produce warnings. Constrained Language mode is reported before this, on its own.
2. **Download check.** Setup works out which downloads this run needs and tests those hosts through the same proxy. Every unreachable host is listed in one message, with the reason, before anything is installed.
3. **Python.** CPython 3.13.16 comes from the official nuget.org package, verified by size and SHA-512, and is extracted into `automation/runtime/python/`. There is no installer, no *Installed apps* entry and no registry or PATH change. On a blocked network, download `https://api.nuget.org/v3-flatcontainer/python/3.13.16/python.3.13.16.nupkg` elsewhere and place it, still named `python.3.13.16.nupkg`, in `automation/runtime/installers/`. Setup uses it when its size and SHA-512 match, and deletes it otherwise.
4. **Environment.** `automation/.venv/` is created from that runtime. It is rebuilt when the Python version or the project folder changes (after moving or copying the project); the previous one is kept as `.venv.backup-*`.
5. **Packages.** Pinned wheels are installed from `automation/requirements.txt`. Every run checks the exact versions and runs `pip check`.
6. **ODBC driver.** Microsoft ODBC Driver 18 or 17 is used, preferring 18. If neither is installed, the signed Driver 18 (x64) MSI is downloaded and installed after an administrator approval. Setup waits while another installation is running, and asks for approval again if Windows Installer was still busy. Exit code 3010 (restart recommended) lets the run continue.
7. **Chromium.** Playwright's full Chromium is installed under `automation/browsers/`. Every run starts it once, headless, to prove it works. The same binary runs headless and visible sessions.

Setup records native command output, preflight problems, unreachable hosts and failed download attempts in `automation/runtime/logs/setup-<UTC>.log`. The final error is shown in the terminal. A required Windows restart stops the run; restart and run the launcher again.

Inherited settings that redirect or break Python and its tools, such as `PYTHONHOME`, `PYTHONPATH`, `PIP_TARGET` or `NODE_OPTIONS`, are ignored for the launcher's own process. Your package index, certificate and proxy settings are kept.

### Proxies and certificates

- When `HTTPS_PROXY` is not set, setup asks Windows (including PAC scripts) which proxy it uses for `pypi.org` and uses that proxy for all downloads. Unless `NO_PROXY` is already set, the Windows proxy bypass list becomes `NO_PROXY`.
- pip uses the Windows certificate store. For Playwright's downloader, the Windows root and intermediate certificates are exported to `automation/runtime/certs/windows-ca.pem` unless `NODE_EXTRA_CA_CERTS` is already set.
- Proxies that require Windows authentication (NTLM/Kerberos, HTTP 407) work for the Python and ODBC downloads but not for pip or Playwright. Ask IT for an exception for the hosts in [Requirements](#requirements), or point `HTTPS_PROXY`, `PIP_INDEX_URL` and `PLAYWRIGHT_DOWNLOAD_HOST` at approved internal endpoints.

For another computer, download a fresh copy and sign in there. Do not copy `.venv/`, `.auth/`, `browsers/`, `runtime/` or logs. The saved login is protected for one Windows user on one computer.

## SQL execution behavior

- Only top-level `.sql` files are selected, sorted by filename. Use names such as `01_...`, `02_...` to make the order explicit.
- Files must be UTF-8 or UTF-8 with BOM containing plain T-SQL. UTF-16 ("Unicode") files, and ANSI files containing non-ASCII characters, are rejected with the file name.
- The exact ordered batches are captured before access changes. Edits or additional files during the run are not picked up.
- A standalone `GO` line, optionally followed by a `--` comment, separates batches. `GO n`, sqlcmd directives and variable substitution are not supported.
- SQL connections use encryption and certificate validation. While a new firewall rule (error 40615) or JIT login (error 18456) becomes active, connecting is retried as Azure SQL recommends: after 5 s, doubling up to 60 s, for at most 5 minutes and never past the credential expiry. Other connection errors stop after 3 attempts. A `SELECT 1` preflight runs before the scripts.
- If Azure SQL reports that it sees a different public address than the firewall rule (error 40615), the run stops and names the `PUBLIC_IP` value to add.
- Each script uses a separate transaction. A failed script is rolled back, and the normal configuration stops execution. Successful earlier scripts remain committed. Scripts are never retried.
- Scripts must not issue their own `COMMIT` or `ROLLBACK`, change databases or connection settings, or contain statements incompatible with transactions.
- Credential expiry is checked before connecting, before each script, batch and result fetch, and before commit.

The report retains up to 100 rows per result set by default while draining the remaining rows. Keep queries bounded and avoid returning data unsuitable for local storage.

## Results and exit codes

The launcher exits with **0** on success and **1** for a handled failure. A successful run with two scripts includes these fields:

```json
{
  "status": "success",
  "sql_execution": {
    "total_scripts": 2,
    "scripts_executed": 2,
    "scripts_failed": 0,
    "sql_connection": {"attempts": 1, "waited_seconds": 0.0}
  },
  "firewall": {"public_ip": "203.0.113.25", "public_ip_source": "auto_direct", "rule_name": "lcsjit-1a2b3c4d"},
  "lcs_date_format": "us_12h",
  "cleanup": {
    "status": "success",
    "scope": "source_ip_firewall_rule",
    "sql_credentials_revoked": false
  }
}
```

This is a shortened example. Failure reports identify `failed_at_step` and include an actionable message and a `diagnostic` section with only class names, codes, categories and file names. Failures after the configuration loaded also write `automation/logs/diagnostics/<command>-<UTC>.json`. `warnings` lists problems that did not stop the run, such as a sign-in file that could not be refreshed. `lcs_date_format` records how LCS displayed expiry dates on this computer.

If a valid existing firewall rule for the same address was reused, cleanup is `not_needed` and `rule_name` is `null`: the tool does not remove rules it did not create. A cleanup failure makes the overall run fail even if SQL succeeded.

## Security and cleanup

- SQL passwords are kept in process memory, not saved in config or reports.
- The saved sign-in is kept in `automation/.auth/`: an encrypted state file, whose key is protected with DPAPI for the current Windows user, and the browser profile (`*.profile`), which holds the sign-in cookies. Treat the folder as a secret. A key from another user or computer, or a damaged one, is set aside as `*.stale-<UTC>` when you sign in again. To use your own key instead, set `LCS_AUTH_KEY` to a Fernet key from your secret manager; state saved with one key cannot be read with another.
- `main.py import-auth` imports the sign-in from Microsoft Edge with the LCS environment page open, when Edge was started with `--remote-debugging-port=9222` and a separate `--user-data-dir` (Edge 136 and later ignore the port for the default profile). Only localhost debugging addresses are accepted.
- Screenshots mask the credential container before image encoding. Unknown and login pages are fully masked.
- Do not enable browser traces, HAR files, videos, network captures or Playwright debug logging for live sessions.
- Reports can contain database names, usernames, query results and other business data. Protect `automation/logs/`.
- Cleanup removes only the exact name, IP and service rule created by the run, after checking a freshly loaded grid. **Firewall removal is not SQL credential revocation**; issued credentials may remain valid until their expiry.
- A run reuses an unexpired rule that already exists for its public IP, and never removes it. Computers behind the same public IP therefore share one rule, which disappears when the run that created it ends. Avoid overlapping runs from such computers.
- Process termination, a host crash or power loss can prevent cleanup. The run's `owned_rule.json` records the rule identity for manual recovery. Remove only that rule after verifying it in LCS.

Use an approved host and account. Local locks prevent overlapping runs within this installation, not across computers.

## Troubleshooting

| Symptom | What to check |
|---|---|
| First run creates `config.yaml` and stops | Expected on a fresh download. Fill in the URL and justification, review the reason, then rerun. |
| "running scripts is disabled" or "is not digitally signed" | Start with `.\run.cmd` instead of `./run.ps1`. If that fails too, Group Policy sets the execution policy (`Get-ExecutionPolicy -List` shows it under `MachinePolicy` or `UserPolicy`). For `RemoteSigned`, run `Get-ChildItem -Recurse \| Unblock-File` in the project folder, or use `git clone`. For `AllSigned` or `Restricted`, ask IT to allow or sign the project's scripts. |
| "Setup cannot continue on this computer" | Every listed item is a separate blocker. Typical fixes: move the project to `C:\LCSJIT`, use `.\run.cmd` (64-bit PowerShell), close the ISE, free disk space. |
| "PowerShell runs in ConstrainedLanguage mode" | Application control (AppLocker/WDAC) restricts PowerShell. Ask IT to allow `run.ps1` and `automation\setup.ps1`. |
| "hosts that cannot be reached" | Ask IT to allow the listed hosts, or use internal endpoints (`HTTPS_PROXY`, `PIP_INDEX_URL`, `PLAYWRIGHT_DOWNLOAD_HOST`). For Python only, the offline `.nupkg` drop-in works. |
| Python dependencies or Chromium fail to install | The message includes the last output and a hint: TLS inspection (install the inspection root certificate), proxy authentication (407), a package mirror without the pins, or long paths. Details are in `automation/runtime/logs/`. |
| ODBC driver installation stops | 1223: the approval prompt was declined; ask IT to install Microsoft ODBC Driver 18 for SQL Server (x64). 1618: another installation kept running; let it finish. 1641: restart Windows, then rerun. Log: `automation/runtime/installers/odbc-install.log`. |
| An earlier version left **Python 3.13.16 (64-bit)** under *Installed apps* | Older versions could register a per-user Python. It is no longer used; remove it in *Settings → Apps → Installed apps* if it points to a deleted folder. |
| "Invalid configuration: (1) ... (2) ..." | Fix each listed problem: the URL part named, the exact reason label, non-empty details, unknown keys, and environment variables named with a `Remove-Item Env:` hint. |
| "Cannot take the launcher lock" or "Another run is active for this environment" | Another run is still going; wait for it to finish. The lock message names other causes, such as missing permissions, a path that is too long or OneDrive locks. |
| "No saved sign-in on this computer yet" or "belongs to a different Windows user or computer" | Expected on a new computer or account. Sign in when asked; the old files are kept as `*.stale-<UTC>`. Use the same Windows account for scheduled runs. |
| `failed_at_step` is `auth_state_write` | Antivirus, backup software or OneDrive locked `automation/.auth`, or its permissions are wrong. Exclude the folder or move the project out of OneDrive. A sign-in file that cannot be refreshed during a normal run is only a warning; one that cannot be read stops the run. |
| `failed_at_step` is `browser_start` | Chromium did not start: a leftover Chromium window using the profile, a missing browser (rerun `.\run.cmd`), or security software blocking `automation\browsers`. |
| `failed_at_step` is `network` | LCS could not be reached. Check Internet, VPN and proxy access to LCS and Microsoft sign-in. |
| `failed_at_step` is `environment` | "did not appear within 60 s": LCS was slow, or your account lacks permission to manage database access. "LCS opened ..., but ENVIRONMENT_URL uses ...": copy the environment-details URL from the LCS host that opened. |
| Expiry date "ambiguous" or "unrecognized format" | Set the LCS language to English (United States) in your LCS user settings. The run refuses to guess credential validity. |
| `failed_at_step` is `sql_connection` | "Azure SQL saw this computer as ...": add the named `PUBLIC_IP` to `config.yaml`. Otherwise check TCP 1433 and 11000–11999, VPN/proxy routing and DNS; network failures show the SQLSTATE and native error codes. |
| `failed_at_step` is `script_execution` | Review the script's sanitized result, permissions, supported T-SQL, timeout and expiry. Earlier successful scripts may already be committed; do not blindly replay them. |
| Cleanup fails | Inspect the run's `owned_rule.json` and remove that exact rule in LCS if it remains. SQL credentials may still be valid. |

Azure SQL requires gateway access on **TCP 1433**. Connections using **Redirect** also require outbound TCP **11000–11999**. An LCS firewall rule does not fix a blocked outbound path. To check gateway reachability:

```powershell
Test-NetConnection -ComputerName "your-server.database.windows.net" -Port 1433
```

## Repository layout

```text
README.md
run.cmd                       # Start here: Windows PowerShell with -ExecutionPolicy Bypass for this process
run.ps1                       # Launcher (also usable directly where policy allows)
config.yaml                   # Personal configuration, generated locally; Git-ignored
.gitattributes                # Keeps Windows line endings for .cmd and .ps1 files
sql_scripts/                  # Reviewed scripts to execute
automation/
  config.template.yaml        # Safe first-download template
  config.advanced.yaml        # Advanced reference profile (rejected until edited)
  defaults.yaml               # Internal settings and calibrated selectors
  setup.ps1                   # Prerequisite setup (preflight, Python, packages, ODBC, Chromium)
  setup_checks.py             # Probes setup runs inside the project environment
  main.py                     # Workflow CLI and reports
  lcs_jit_automation.py       # LCS browser adapter and encrypted login storage
  sql_executor.py             # SQL batching, connection retries and transactional execution
  automation_support.py       # Configuration, diagnostics and shared contracts
  requirements.txt            # Pinned runtime dependencies (name==version only)
  requirements-dev.txt        # Pinned test and type-check tools
  run.cmd                     # Compatibility wrapper with --flags
  tests/                      # Regression tests
  LIVE_TEST_RESULTS.md        # Dated verification evidence and limitations
```

Generated runtime, browser, authentication and log files stay under `automation/` and are excluded from Git.

## Verification and development

See [the verification record](automation/LIVE_TEST_RESULTS.md) for what was verified, where, and what is still pending on Windows.

Run the tests from the project folder after setup, with the project's Python:

```powershell
.\automation\.venv\Scripts\python.exe -m pip install -r automation\requirements-dev.txt
.\automation\.venv\Scripts\python.exe -m mypy --platform win32 automation\automation_support.py automation\lcs_jit_automation.py automation\sql_executor.py automation\main.py automation\setup_checks.py
.\automation\.venv\Scripts\python.exe -m pytest automation\tests -rs
```

Every skip states its reason (`-rs` lists them). The markers are `windows` (Windows-only paths), `powershell` (needs Windows PowerShell, or `pwsh` elsewhere), `chromium` (needs Playwright Chromium in `automation/browsers`, or set `PLAYWRIGHT_BROWSERS_PATH`) and `integration` (runs the real launcher and installers; set `$env:LCSJIT_INTEGRATION = '1'`). Tests remove machine-wide configuration variables, so a `LOGS_PATH` or `PUBLIC_IP` set on the computer cannot change results. The development tools are pinned in `automation/requirements-dev.txt`.

Regression tests use routed browser fixtures and mocked ODBC connections, not live SQL. Passing fixtures do not establish live tenant compatibility.

For Task Scheduler, invoke PowerShell with an absolute launcher path and `-Headless`, for example:

```text
-NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\LCSJIT\run.ps1" -Headless
```

Complete setup and sign-in first under the same Windows account, prevent overlapping instances, and allow interactive sign-in renewal when required.

## References

- [Microsoft: Just-in-time database access](https://learn.microsoft.com/en-us/dynamics365/fin-ops-core/dev-itpro/database/database-just-in-time-jit-access)
- [Microsoft: Azure SQL connectivity architecture](https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture)
- [Microsoft: Troubleshoot Azure SQL connection errors](https://learn.microsoft.com/en-us/azure/azure-sql/database/troubleshoot-common-errors-issues)
- [Microsoft: ODBC Driver for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)
- [Python on nuget.org](https://www.nuget.org/packages/python/3.13.16)
- [Playwright: Browsers, proxies and certificates](https://playwright.dev/python/docs/browsers)
- [pip: HTTPS certificates](https://pip.pypa.io/en/stable/topics/https-certificates/)
- [Chrome: Changes to remote debugging switches](https://developer.chrome.com/blog/remote-debugging-port)
