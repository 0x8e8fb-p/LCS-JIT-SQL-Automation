# LCS JIT SQL Automation

Run local SQL scripts against a Dynamics 365 Finance and Operations sandbox using temporary database access from Lifecycle Services (LCS).

The PowerShell launcher prepares the local runtime, opens a browser when sign-in is needed, requests JIT credentials, executes the scripts, and removes the firewall rule it created. Subsequent runs reuse the saved login while it remains valid.

This project supports **LCS-managed sandbox environments on Windows x64**. It does not support Power Platform admin center (PPAC) access flows. Different LCS interfaces may require changes to the browser adapter.

## Requirements

- Windows x64: Windows 10 version 1809, Windows 11, or Windows Server 2019 or newer. Use a Windows release supported by your organization.
- PowerShell and permission to run the repository's scripts.
- A writable local folder containing the extracted repository.
- An LCS account authorized to manage database access for the target sandbox.
- Internet access for prerequisite downloads, LCS sign-in, and public IP detection.
- Network access to the environment's Azure SQL server.
- Administrator approval if the Microsoft SQL ODBC driver needs to be installed.

You do **not** need to install Python or a browser beforehand. The launcher uses compatible existing prerequisites or installs missing ones. It cannot bypass MFA, Windows UAC, execution policy, endpoint security, or corporate network restrictions.

## Quick start

### 1. Download and extract the repository

Use **Code → Download ZIP** on GitHub and extract the entire archive. Do not run the launcher from inside the ZIP viewer.

If Git is installed, you can clone it instead:

```powershell
git clone https://github.com/0x8e8fb-p/LCS-JIT-SQL-Automation.git
cd LCS-JIT-SQL-Automation
```

For a ZIP download, open PowerShell in the extracted folder containing `run.ps1`.

### 2. Create your configuration

```powershell
./run.ps1
```

On a fresh download, the launcher creates `config.yaml` from the bundled template and stops so you can edit it. **This first invocation returns exit code 1 by design.** It does not install prerequisites, request access, or execute SQL at this stage.

If `config.yaml` already exists, it is not overwritten. Review it before running the launcher: a configured invocation can proceed into SQL execution.

Open `config.yaml` in a text editor. It has four fields:

```yaml
ENVIRONMENT_URL: "https://lcs.dynamics.com/V2/EnvironmentDetailsV3New/123456?EnvironmentId=11111111-2222-4333-8444-555555555555"
ACCESS_REASON: "AX troubleshooting (read-only to AX)"
ACCESS_DETAILS: "Approved sandbox database validation"
FIREWALL_RULE_NAME: "lcsjit"
```

The URL above is an example, not a working environment. Replace it with your sandbox's complete **LCS environment-details URL**, copied from the browser address bar. See [Configuration](#configuration) for the other fields.

Your personal `config.yaml` is excluded from Git. It is not included in a fresh clone, and normal repository updates do not replace it.

### 3. Review the SQL scripts

Place the scripts you intend to execute directly in `sql_scripts/`.

The repository includes two non-mutating examples:

| File | Purpose |
|---|---|
| `01_connectivity.sql` | Returns the database name, server UTC time, and a connectivity result. |
| `02_read_only_validation.sql` | Returns up to ten table names from `INFORMATION_SCHEMA.TABLES`, subject to the account's permissions. |

**Every top-level `.sql` file in this folder is included in the run.** Remove or move any script you do not want executed. Use only reviewed scripts and obtain the required approval before making database changes.

### 4. Prepare and validate the installation

```powershell
./run.ps1 -ValidateOnly
```

This installs missing prerequisites and checks the configuration, script encoding and supported batch syntax, ODBC driver, and browser. It does not sign in to LCS, grant access, or execute SQL.

A successful validation does not prove that the SQL server is reachable, that every T-SQL statement is valid, or that the selected account has permission to execute it.

### 5. Run the workflow

```powershell
./run.ps1
```

If a valid saved login is unavailable:

1. Sign in in the browser window opened by the launcher.
2. Complete MFA if requested.
3. Wait for the configured environment-details page to load.
4. Return to PowerShell and press **Enter**.

The launcher then manages firewall access, requests credentials, executes the scripts, and performs cleanup. Keep the terminal and browser open until the run finishes.

### 6. Check the result

Read the terminal output and the report at:

```text
automation/logs/<UTC timestamp>/report.json
```

Confirm the overall status, the expected number of successful scripts, and the cleanup status. Seeing credentials in LCS is not evidence that SQL executed.

## Configuration

| Field | Required value |
|---|---|
| `ENVIRONMENT_URL` | The complete HTTPS LCS environment-details URL, including its `EnvironmentId` query parameter. Do not use the application URL or LCS project overview. |
| `ACCESS_REASON` | The exact **Reason for access** label shown in LCS. This determines the granted database permissions. |
| `ACCESS_DETAILS` | A non-empty justification entered into the LCS Request access block. Follow your organization's approval policy. |
| `FIREWALL_RULE_NAME` | A temporary rule name containing 1–64 letters, digits, underscores, or hyphens. The first character must be a letter or digit. An existing conflicting rule is never overwritten. |

Supported reason labels:

| LCS reason | Requested access |
|---|---|
| `AX troubleshooting (read-only to AX)` | Read-only access to AX |
| `MR troubleshooting (read-only to MR)` | Read-only access to MR |
| `Performance tuning for AX (write to AX)` | Write access to AX |
| `Troubleshooting and tuning entity store (write to AXDW)` | Write access to AXDW |

Choose the least privilege required by your scripts. A SELECT-only script does not make a write-enabled account read-only. The tool does not parse SQL to enforce read-only access.

The project ID and environment GUID are derived from the URL. The environment heading is read only after the target URL is verified. Driver selection, browser selectors, authentication paths, stop-on-error behavior, and automatic cleanup are handled internally.

URLs must use `https://lcs.dynamics.com/V2/EnvironmentDetailsV3New/<project ID>` with a canonical lowercase environment GUID and no fragment. Duplicate YAML keys, unknown fields, and ambiguous target identities are rejected. UTF-8 BOM and surrounding whitespace are accepted.

### Advanced profiles

Most users should use the four-field configuration. For custom script locations, network egress settings, timeouts, or selector changes, review [the advanced reference profile](automation/config.advanced.yaml) and create a profile for your environment:

```powershell
./run.ps1 -Config "automation/my-profile.yaml"
```

The reference contains environment-specific settings and an explicit Driver 17 selection. Do not run it unchanged against a different environment. Relative paths inside a profile resolve from that profile's directory; the `-Config` argument itself resolves from the root launcher's directory.

Uppercase environment variables can override the four user-facing fields. Advanced overrides require a profile with explicit `selectors`. Stale variables such as `DISABLE_ACCESS_AFTER`, `SQL_SCRIPTS_PATH`, or `ACCESS_LEVEL` are rejected with the minimal profile rather than silently changing its behavior.

## Launcher options

| Command | Behavior |
|---|---|
| `./run.ps1` | Prepare prerequisites, reuse a valid login or prompt for sign-in, then run with a visible browser. |
| `./run.ps1 -ValidateOnly` | Prepare prerequisites and perform local checks only. |
| `./run.ps1 -LaunchOnly` | Prepare prerequisites, validate, and save a fresh login. Do not grant access or run SQL. |
| `./run.ps1 -ForceInteractive` | Require a fresh interactive login, then run the complete workflow. |
| `./run.ps1 -Headless` | Run without a visible browser using saved authentication. It does not prompt for sign-in. |
| `./run.ps1 -Config "my-profile.yaml"` | Use an alternate configuration. |

Use the mode switches separately. `-Config` can be combined with a mode. Authentication-only modes still perform local configuration, script, and runtime validation first.

The compatibility batch wrapper is at `automation/run.cmd`. For example, `automation\run.cmd --validate-only` delegates to the same PowerShell launcher.

## First-time setup and repeat runs

The launcher:

1. Finds an x64 Python 3.10–3.13 interpreter. If none is available, it downloads Python 3.13.16, verifies its checksum and publisher signature, and installs it under `automation/runtime/python/`. Nothing is added to PATH and no system-wide Python is changed: the launcher extracts the interpreter from the verified download, which creates no Windows Installer product, no *Installed apps* entry and no `PythonCore` registry entry, so deleting or moving the project folder cannot leave a stale Python registration behind. Only if MSI extraction is blocked by policy does it fall back to the official installer, which registers a per-user `Python 3.13.16 (64-bit)` entry that should be removed before the project folder is deleted or moved.
2. Creates an isolated environment at `automation/.venv/`. An unusable copied environment is preserved as a `.venv.backup-*` before rebuilding.
3. Installs the pinned dependencies from binary wheels. On repeat runs it checks installed versions and imports, and runs `pip check` to detect compatibility problems.
4. Uses Microsoft ODBC Driver 18 or 17, preferring 18 when both are installed. If neither is available, it downloads the current Microsoft ODBC Driver 18 (x64) MSI (18.7 at the time of writing) from Microsoft's stable download link, verifies its publisher signature, and requests elevation when needed. Driver 18 does not require a separately installed Visual C++ Redistributable.
5. Installs Playwright Chromium under `automation/browsers/` and checks that it can launch.
6. Validates the inputs before making LCS access changes.

A required Windows restart stops the run. Restart and invoke the launcher again. Installer logs are stored in `automation/runtime/installers/`.

For another machine, download a fresh source copy and authenticate there. Do not transfer `.venv/`, `.auth/`, `browsers/`, `runtime/`, logs, or caches. Windows-protected authentication is tied to the Windows identity and is not portable to an unrelated machine or user.

## SQL execution behavior

- Only top-level `.sql` files are selected, sorted by filename. Use names such as `01_...`, `02_...` to make the order explicit.
- Files must be UTF-8 or UTF-8 with BOM, containing plain T-SQL. Subfolders are not scanned.
- The exact ordered batches are captured before access changes. Edits or additional files during JIT setup are not picked up by that run.
- A standalone `GO` line, optionally followed by a `--` comment, separates batches. `GO n`, sqlcmd directives, and variable substitution are not supported.
- SQL connections use encryption and certificate validation. A `SELECT 1` preflight runs before the scripts.
- Each script uses a separate transaction. Result sets are drained before commit. A failed script is rolled back, and the normal configuration stops execution.
- Successful earlier scripts remain committed if a later script fails. The tool does not automatically retry script execution or provide an all-files transaction.
- Scripts must not issue their own `COMMIT` or `ROLLBACK`, change databases or connection settings, or contain statements incompatible with transactions. Such statements can invalidate the rollback guarantees.
- Credential expiry is checked before connection, batches, result fetches, and commit. Query timeouts are enforced, but an in-flight synchronous query cannot be interrupted exactly at expiry.

The report retains up to 100 rows per result set by default while draining the remaining rows. This is not a total byte limit: large cells or many result sets can still produce a large report. Keep queries bounded and avoid returning data unsuitable for local storage.

## Results and exit codes

The launcher exits with **0** on success and **1** for a handled workflow failure. It preserves the Python command's exit status. A successful run with two scripts includes these fields:

```json
{
  "status": "success",
  "sql_execution": {
    "total_scripts": 2,
    "scripts_executed": 2,
    "scripts_failed": 0
  },
  "cleanup": {
    "status": "success",
    "scope": "source_ip_firewall_rule",
    "sql_credentials_revoked": false
  }
}
```

This is a shortened example; the actual report includes per-script results and timings. `scripts_executed` counts successful scripts, not failed attempts. Failure reports identify `failed_at_step` and include an actionable, sanitized error message.

If a valid existing firewall rule was reused, cleanup can be reported as `not_needed`: the tool does not remove rules it did not create. A report with `failed_at_step: sql_connection` means script execution did not begin. A cleanup failure makes the overall run fail even if SQL succeeded.

## Security and cleanup

- SQL passwords are kept in process memory, not saved in config or reports.
- Saved browser authentication is encrypted. On Windows, its local encryption key is protected with DPAPI under the current identity. Protect `automation/.auth/`, logs, process memory, and crash dumps with appropriate OS controls.
- Screenshots mask the configured credential container before image encoding. Unknown and login pages are fully masked. Changed credential layouts require reviewing the adapter's selectors and masks.
- Do not enable browser traces, HAR files, videos, network captures, or Playwright debug/API logging for live sessions.
- Reports can contain database names, usernames, query results, and other business data. Sanitizing known passwords is not a general data-loss-prevention mechanism.
- Cleanup removes only the matching name/IP/service firewall rule created by the run and checks its absence in a refreshed grid. A valid existing rule can be reused but is not owned or deleted.
- **Firewall removal is not SQL credential revocation.** Issued credentials may remain valid until their expiry.
- Process termination, a host crash, or power loss can prevent cleanup. The run's `owned_rule.json` records the rule identity for manual recovery. Remove only the recorded rule after verifying it in LCS; do not delete unrelated entries.

Use an approved host and account. Shared egress IPs can affect other database sessions. Local locks prevent overlapping launcher runs within this installation, but they do not coordinate other machines or manual LCS requests.

## Troubleshooting

| Symptom | What to check |
|---|---|
| First run creates `config.yaml` and stops | Expected on a fresh download. Fill in the URL and justification, review the reason and rule name, then rerun. |
| PowerShell refuses to run the script | Follow your organization's script-signing and execution-policy requirements. The launcher does not change policy. |
| Prerequisite download or installation fails | Check Internet/proxy access, disk space, endpoint security, and installer logs under `automation/runtime/installers/`. Approve UAC when required. |
| Invalid configuration | Check the URL, exact reason label, non-empty details, rule-name format, duplicate keys, and stale environment overrides. |
| Another launcher is active | Wait for the current run to finish. Do not delete lock files or launch overlapping grants. |
| Saved authentication is missing or expired | Run `./run.ps1 -ForceInteractive` to sign in again and continue, or `-LaunchOnly` to refresh login without granting access. Use the same Windows identity for scheduled runs. |
| Python installation stops on a no-op install, or fails with 1603 | An earlier fallback install registered a per-user Python for a folder that has since been deleted or moved. Remove the leftover **Python 3.13.16 (64-bit)** entry in *Settings → Apps → Installed apps*, then rerun. The normal setup path extracts the interpreter and registers nothing. |
| LCS controls or credential rows cannot be found | Confirm this is an LCS-managed sandbox and that your account has permission. A changed UI may require adapter calibration. Do not share credentials or raw page dumps for debugging. |
| `failed_at_step` is `sql_connection` | Check DNS, outbound ports, VPN/proxy routing, source egress IP, TLS, and the active JIT/firewall window. Database movement can change the SQL hostname. |
| `failed_at_step` is `script_execution` | Review the script's sanitized result, granted permissions, supported T-SQL, timeout, and expiry. Earlier successful scripts may already be committed; do not blindly replay them. |
| Cleanup fails | Inspect the run's `owned_rule.json` and remove that exact rule in LCS if it remains. SQL credentials may still be valid. |
| The report cannot be written | Check permissions and free space in `automation/logs/`. The final report-write failure returns failure even if SQL completed. |

Azure SQL requires gateway access on **TCP 1433**. Connections using **Redirect** also require outbound TCP **11000–11999** to the appropriate regional Azure SQL endpoints. An LCS firewall rule does not fix a blocked outbound path from your machine. HTTPS proxy egress and SQL egress can differ.

To check gateway reachability, replace the hostname with the current SQL server shown in LCS:

```powershell
Test-NetConnection -ComputerName "your-server.database.windows.net" -Port 1433
```

A successful TCP probe does not establish SQL authentication, permissions, or Redirect connectivity. Do not disable TLS validation or network security to make a connection succeed.

## Repository layout

```text
README.md
run.ps1
config.yaml                   # Personal configuration, generated locally; Git-ignored
sql_scripts/                  # Reviewed scripts to execute
  01_connectivity.sql
  02_read_only_validation.sql
automation/
  config.template.yaml        # Safe first-download template
  config.advanced.yaml        # Advanced reference profile
  defaults.yaml               # Internal settings and calibrated selectors
  setup.ps1                   # Prerequisite installation helpers
  main.py                     # Workflow CLI and reports
  lcs_jit_automation.py        # LCS browser adapter and encrypted login storage
  sql_executor.py             # SQL batching and transactional execution
  requirements.txt            # Pinned runtime dependencies
  run.cmd                     # Compatibility batch wrapper for run.ps1
  tests/                      # Regression tests
  LIVE_TEST_RESULTS.md        # Dated verification evidence and limitations
```

Generated runtime, browser, authentication, and log files stay under `automation/` and are excluded from Git. When sharing the project, use a fresh clone or source archive rather than copying a working installation.

## Verification and development

The latest recorded audit ran the visible and headless launchers against one LCS sandbox. Both runs executed the two SELECT samples successfully, and separate browser inspections confirmed that no firewall rules remained. The final regression suite had **88 passing tests**, with clean runtime typechecking. A later setup-robustness change that recovers from a deleted/moved local Python folder was verified separately; the suite then had **98 passing tests**. The Python install path was then made registration-free — the launcher extracts the verified interpreter instead of registering a per-user Python, and a real extraction was re-verified on Windows x64 with **99 passing tests**. See [the verification record](automation/LIVE_TEST_RESULTS.md) for dates, measurements, and scope.

A source-only download copy passed prerequisite setup and repeat validation. Actual missing-driver installation and UAC on a pristine Windows machine were not verified because the test host already had Driver 17. These results do not certify other tenants, arbitrary write scripts, or every supported Windows/Python combination. See [the verification record](automation/LIVE_TEST_RESULTS.md) for dates, measurements, and scope.

To run local checks after prerequisite setup, use PowerShell from the repository root:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path (Get-Location) "automation/browsers"
./automation/.venv/Scripts/python.exe -m pip install -r automation/requirements-dev.txt
./automation/.venv/Scripts/python.exe -m mypy --cache-dir automation/.mypy_cache automation/automation_support.py automation/lcs_jit_automation.py automation/sql_executor.py automation/main.py
./automation/.venv/Scripts/python.exe -m pytest automation/tests
```

Regression tests use routed browser fixtures and mocked ODBC connections, not live SQL writes. Update dependency pins and browser defaults together with their relevant tests. Passing fixtures do not establish live tenant compatibility.

For Task Scheduler, invoke PowerShell with an absolute launcher path and `-Headless`, for example:

```text
-NoLogo -NoProfile -File "C:/Tools/LCS-JIT-SQL-Automation/run.ps1" -Headless
```

Complete setup and login first under the same Windows identity, prevent overlapping instances, and allow interactive login renewal when required. The repository does not create scheduled tasks or alter Conditional Access policies.

## References

- [Microsoft: Just-in-time database access](https://learn.microsoft.com/en-us/dynamics365/fin-ops-core/dev-itpro/database/database-just-in-time-jit-access)
- [Microsoft: Azure SQL connectivity architecture](https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture)
- [Microsoft: ODBC Driver for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)
- [Playwright: Authentication](https://playwright.dev/python/docs/auth)
