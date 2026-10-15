# Setup verification and historical live results

## Registration-free local Python installation — 2026-10-15

**Reviewed inconsistency:** the setup contract promises a project-local interpreter ("no PATH changes", "no system-wide Python"), but the preferred install path ran the official per-user bundle installer. A per-user bundle install registers Windows Installer products, an *Installed apps* entry and `HKCU\Software\Python\PythonCore\3.13\InstallPath`, all pointing at `automation/runtime/python/`. Deleting or moving the project folder — which the documentation itself asks for when moving machines ("download a fresh source copy", do not transfer `runtime/`) — therefore left a registered Python whose `InstallDirectory` no longer existed. Every later run was a no-op *Modify*, `/uninstall` failed (1603 from `pip.msi`: the earlier failure on this host), and other Python tooling still saw a bogus 3.13 installation.

**Confirmed on this host before the change:** `HKCU\Software\Python\PythonCore\3.13\InstallPath` pointed at `...\automation\runtime\fresh setup verification\automation\runtime\python\`, a leftover verification copy, while the per-user products *Python 3.13.16 Core Interpreter / Executables / Standard Library / Development Libraries / pip Bootstrap* and the `Python 3.13.16 (64-bit)` uninstall entry stayed registered. `py -3.13` and `Get-RegistryPythonCandidates` both resolved to that copy, and each registered interpreter was probed twice because `ExecutablePath` and the `InstallPath` default are the same path.

**Change:** `Install-LocalPython` now extracts the attached MSI container from the checksum- and publisher-verified `python-3.13.16-amd64.exe` (`expand.exe` plus `msiexec /a` for the core, exe, dev and lib payloads) into `automation/runtime/python/` as its preferred path. An administrative install writes files only: no Windows Installer product, no *Installed apps* entry, no PATH entry and no `PythonCore` registry entry is created, so the stale-registration dead end cannot recur and nothing accumulates per project folder. Every extracted payload is now checked for the MSI (OLE2) header before `msiexec` runs, so a container-layout change fails with a precise message instead of installing a wrong file. The official installer remains as a documented fallback for hosts where MSI administrative installation is blocked; it now sets `Include_pip=1` explicitly and states that it registers a per-user Python entry. Duplicate registry candidates are probed once.

**Verified on this host (2026-10-15) in a scratch folder, without touching project state:** the real `python-3.13.16-amd64.exe` (29,935,584 bytes) was downloaded with SHA-256 and Python Software Foundation Authenticode verification; `expand.exe` plus `msiexec /a` produced a usable interpreter at `runtime/python/python.exe`: Python **3.13.16**, 64-bit pointers, `ssl`, `sqlite3`, `ctypes`, `venv` and `ensurepip` importable, `Include/Python.h` and `libs/python313.lib` present. That interpreter created a virtual environment with **pip 26.2.1**; `pip install --only-binary=:all: -r automation/requirements.txt` exited **0** and `pip check` reported **no broken requirements**. The Windows registration list (per-user Python products and *Installed apps* entries) was byte-identical before and after the extraction, confirming that the preferred path registers nothing.

- Unit tests cover the preferred extraction path and that it does not run the official installer (`test_install_local_python_extracts_without_windows_installer_registration`), the blocked-extraction fallback (`test_install_local_python_falls_back_to_official_installer_when_extraction_fails`), the restart stop (`test_install_local_python_restart_requirement_stops_instead_of_extracting`), the container extraction (`test_unpack_python_installer_extracts_attached_msi_container`) and a layout-change refusal (`test_unpack_python_installer_rejects_unexpected_container_payload`).
- Full regression suite: **99 passed** (no skips). Typechecking of the four runtime modules: clean. `./run.ps1 -ValidateOnly`: exit **0**.
- **Limits:** the extraction ran on this Windows x64 host. A host where MSI administrative installation is blocked by policy still falls back to the registered per-user installer, which is mock-tested only. The pre-existing stale `Python 3.13.16 (64-bit)` registration from earlier runs on this host was deliberately left in place; remove it in *Settings → Installed apps* if a clean machine state is required. The extracted interpreter still has no `pip` module of its own and no tcl/tk, documentation or test suite (the launcher's own environment provides pip, and that environment is what was verified). A pristine VM, non-admin policy behavior and live LCS/SQL execution were not part of this verification.

## Stale local-Python repair verification (historical; superseded by the registration-free install above) — 2026-10-15

**Reviewed failure:** on a host whose project-local Python 3.13 folder had been deleted or moved, `./run.ps1` stopped with installer exit **1603**. The logged cause (`python-uninstall.log`) is `Failed to uninstall MSI package` for `pip_JustForMe`: the WiX Burn registration still pointed at an InstallDirectory where `python.exe` no longer existed, so neither a reinstall (no-op Modify) nor the previous uninstall-then-reinstall repair could succeed.

**Change (first repair, later made the preferred path):** `Install-LocalPython` no longer uninstalls the stale bundle. It extracts the attached MSI container from the already checksum- and publisher-verified `python-3.13.16-amd64.exe` with `expand.exe` and runs `msiexec /a` for the core, exe, dev and lib payloads directly into `automation/runtime/python/`. This is a per-user file extraction: no ARP entry, PATH entry, or system-wide Python is created, and the temporary extraction folder is deleted afterwards. At the time of this record the extraction ran only after the official installer had already failed; it is now attempted first, with the official installer as the fallback.

**Verified on this host (2026-10-15):** real installer download with SHA-256 and Authenticode verification, with system-Python and registry discovery overridden to simulate the deleted previous folder. The repair path produced a usable **Python 3.13.16 x64** interpreter (OpenSSL 3.5.9, `ssl`, `sqlite3`, `ctypes`, `venv`, `ensurepip`, 64-bit pointers, development headers present) which created a virtual environment with **pip 26.2.1**; all pinned wheels installed with `--only-binary=:all:` and `pip check` reported **no broken requirements**. A repeat discovery returned the same `automation/runtime/python/python.exe`, confirming the repair is not repeated once the interpreter exists. An installer that fails outright (rather than no-op'ing) now falls back to the same extraction, while a required Windows restart still stops the run.

- Unit tests at that time covered the repair branch (no-op and failed installer variants), the restart behavior, and the container extraction (`test_install_local_python_repairs_stale_wix_burn_registration`, `test_install_local_python_restart_requirement_stops_instead_of_extracting`, `test_unpack_python_installer_extracts_attached_msi_container`). The first of those names was replaced when the extraction became the preferred path.
- Full regression suite: **98 passed** (no skips). Typechecking of the four runtime modules: clean. `./run.ps1 -ValidateOnly`: exit **0**.
- **Limits:** the stale-registration condition was simulated by overriding discovery on this host; the host's own Python installations were not uninstalled, and the extraction path itself ran for real. The extracted interpreter is a per-user file copy: it has no `pip` module of its own (the launcher creates its own environment and uses that environment's bundled pip, which was verified) and no tcl/tk, documentation, or test suite. The stale Burn registration is intentionally left in place, so Windows can still list the earlier Python 3.13.16 entry in *Apps & features*. Non-admin MSI-administrative-install policy, a pristine VM, and live LCS/SQL execution were not part of this verification.

## End-to-end audit — 2026-10-13

**Current result: real SQL execution and owned-rule cleanup verified through the root launcher.** The earlier connectivity-only conclusion below is historical and is superseded by this audit.

### Confirmed inconsistencies repaired

- A GitHub clone had no `config.yaml` because the personal config is ignored. The launcher now exclusively creates a safe four-field config from the versioned `automation/config.template.yaml`, then stops before setup/access changes so the user can fill it in. Existing configs are never overwritten; missing alternate configs are not silently created.
- Floating package versions and import-only probes could diverge across fresh/repeat runs. Runtime and transitive dependencies are now pinned to the verified versions; setup verifies versions/imports, installs wheels only and runs `pip check` every time. Incomplete downloads fail before installation.
- Duplicate YAML keys could silently replace settings; outer whitespace/BOM handling and ambiguous environment GUID/query inputs were inconsistent. Duplicate keys and ambiguous/noncanonical target identities now fail closed; BOM/outer whitespace work. Stale advanced environment overrides cannot silently disable cleanup or redirect scripts/auth in a minimal profile.
- Script files were validated before JIT but rediscovered/read afterward. The CLI now snapshots the exact ordered batches before access changes; edits/additions during setup cannot silently alter that run's SQL.
- Diagnostic disk failures could obscure cleanup errors. Auxiliary diagnostic failures are now explicitly recorded while preserving cleanup/browser outcomes. Final report-write failure remains fatal.
- A stale fixed-name encrypted temp file could block login refresh. Auth writes use unique exclusive encrypted temporary files and clean them up.
- Browser mutations now reverify environment identity; recognized Entra login redirects are classified as authentication rather than an environment error. Tests no longer depend on a user's personal root config.

### Verified artifacts and checks

- Actual `./run.ps1`, existing same-identity encrypted login, root four-field config, and exactly the two reviewed SELECT-only scripts: **exit 0**, report **success**, **2 scripts executed**, **0 failed**, expected connectivity result `[[1]]`, and **cleanup success**. Measured automation pipeline: **223.156 seconds**; SQL execution: **1.031 seconds**. This is one sample-input measurement, not an every-run timing guarantee.
- Evidence: `automation/logs/audit_live_launcher.log`, `.exit`, and `automation/logs/2026-10-13_09-30-37_653310/report.json`. Credentials stayed encrypted/in-memory; no password is included here.
- A separate fresh browser reopened the verified firewall grid afterward: **0 firewall rules**, automation rule absent. Evidence: `automation/logs/audit_independent_firewall.json`.
- A source-only download-style copy (tracked working-tree files plus new source files, no virtual environment/auth/runtime) created the safe config, then installed a real fresh virtual environment, pinned dependencies and Chromium. Local/runtime validation passed with **exit 0**; repeat validation from another working directory passed without reinstalling. Evidence: `audit_download_setup.log`, `.exit`, and `audit_download_repeat.log`.
- Windows x64 **Python 3.10** wheels for all pins downloaded successfully; the pin set also resolved in the previously installed **Python 3.13.16** clean-copy interpreter. Actual code/tests ran on Python 3.11; wheel resolution is not full runtime certification of every minor version.
- A second actual `./run.ps1 -Headless` run passed with **exit 0**, **2 executed / 0 failed**, connectivity result `[[1]]`, and successful owned-rule cleanup. Pipeline: **176.765 seconds**; SQL: **0.875 seconds**. Evidence: `audit_live_repeat.log`, `.exit`, `2026-10-13_09-36-33_518217/report.json`. A separate final browser inspection again found **0 firewall rules** (`audit_final_verification.json`). The visible/headless timings are observations, not a speedup claim or timing guarantee.
- Final regression suite: **88 passed**. Typechecking of all four runtime modules passed. Tests cover configuration, bootstrap orchestration, browser fixtures, SQL mock transactions, script snapshots, audit-write failures, version drift and encrypted login. Two launcher tests briefly failed while the real run intentionally held its local lock; they passed after the live run ended, and the final full suite passed without skips or weakened assertions.

### Limits

No pristine VM was available. The host already has Microsoft ODBC Driver 17, so actual missing-driver/UAC installation of Driver 18.7 is **not certified**; official download/signature and mocked install/failure/restart branches are verified. Python-missing installation was exercised with a real local installer in the earlier clean-copy test below, not by uninstalling host Python. Interactive MFA/UAC still require user action. Only approved SELECT samples ran against this one LCS-managed sandbox; no arbitrary writes, other tenants, PPAC, other OS/architectures or unattended expired-MFA recovery are certified. Local locks do not serialize manual operations/other machines, and termination/power loss cannot guarantee cleanup. The repository changes have not been committed or pushed by this audit; a remote GitHub download receives them only after an authorized publication step.

## Simplified setup verification — 2026-10-13

Delivered interface: root **`run.ps1`**, **`config.yaml`**, **`sql_scripts/`**, and **`automation/`** only (excluding hidden Git metadata). Implementation, setup helpers, defaults, advanced profile, docs, tests, logs, authentication and generated runtime are inside `automation/`. The normal config contains exactly `ENVIRONMENT_URL`, `ACCESS_REASON`, `ACCESS_DETAILS`, and `FIREWALL_RULE_NAME`; URL identity, permission metadata, installed ODBC driver and encrypted-auth paths are derived internally.

Verified through Windows PowerShell 5 and the actual root launcher:

- `./run.ps1 -ValidateOnly` automatically installed missing **project-local Chromium** and passed configuration/script/runtime validation for the two sample scripts. Exit **0**.
- A clean source copy under `automation/runtime/fresh setup verification/` started with **no copied Python, virtual environment, packages, browser or auth files**. Its `Find-SupportedPython` discovery helper alone was overridden to return none, exercising the no-system-Python branch without uninstalling the host's interpreter. Everything else used real download/verification/installation and launcher logic.
- That copy downloaded Python **3.13.16**, checked the official SHA-256 and Python Software Foundation Authenticode signature, installed it locally, created a fresh virtual environment, installed requirements, passed `pip check`, downloaded Chromium and passed runtime validation. Exit **0**. `sys.base_prefix` was checked against the copy's local `automation/runtime/python/`; Python version was checked as **3.13.16**.
- A repeat invocation from a different working directory passed without installation output. No authentication files were copied or created by validation. Evidence: `automation/logs/fresh_setup.log`, `fresh_setup.exit`, `fresh_setup_repeat.log` and `setup_validation.log`.
- The official **ODBC Driver 18.7.1.1 x64 MSI** downloaded successfully and its Authenticode status was **Valid**, publisher **Microsoft Corporation**. The real machine already has Driver 17, which validation used. **The MSI was not installed** and the existing system driver was not replaced. Missing-driver orchestration, signature/checksum refusal and installer failure/restart exit codes were tested with mocks. UAC approval/driver installation on a pristine host is still not live-verified.
- Typechecking passed for the four runtime Python modules. The complete suite plus final affected-test reruns passed **69 tests**, covering four-field configuration, internal paths, Driver 17/18 selection, stable environment locking, launcher modes/exit propagation, setup first/repeat runs, invalid installer refusal, encrypted auth, browser fixtures, SQL mock transactions and cleanup.
- Relocation initially exposed test-import failures, fixed by internal `pytest.ini`. A real first-run check also exposed PowerShell 5 treating expected native stderr from a missing Chromium probe as fatal; probes now retain false/exit-code semantics while leaving the caller's strict error policy intact. Both fixes were rerun successfully.

**Scope/limitations:** this is a real clean-copy setup test on the existing Windows x64 host, not a pristine VM or cross-platform certification. MFA/UAC/corporate policies and network access can require user/admin action. No LCS grant or live SQL execution was performed for this packaging/setup change. Browser regression fixtures pass, but they do not replace live tenant or SQL verification. At that earlier setup-only check no new live SQL run was attempted. The latest end-to-end audit above supersedes its connectivity conclusion.

## Historical live verification — LCS sandbox (2026-10-08)

The following evidence predates the folder/config simplification. Historical paths written as `logs/...` now reside under **`automation/logs/...`**. Historical test counts and explicit Driver 17 configuration describe that earlier run, not a new live run of the simplified launcher.

### Outcome

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
