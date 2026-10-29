"""CLI for the config.yaml / run.ps1 LCS JIT workflow."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import time
import traceback
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
COMMANDS = ['run', 'bootstrap', 'import-auth', 'validate', 'check-auth']
_IMPORT_ERROR: ImportError | None = None

try:
    from playwright.sync_api import sync_playwright

    from automation_support import (AutomationError, Config, Credentials, LCS_HOSTS, describe_error, environment_lock,
                                    explain_error, timestamp, utcnow)
    from lcs_jit_automation import LCSAutomation, get_public_ip, save_auth
    from sql_executor import PreparedScript, execute_sql_scripts, prepare_scripts, scrub, validate_scripts
except ImportError as import_error:  # damaged or partial environment: still answer in JSON
    _IMPORT_ERROR = import_error


def import_failure_report(error: ImportError) -> dict[str, Any]:
    """Report without project imports; any of them may be what failed."""
    name = (error.name or '').split('.')[0]
    known = {'playwright', 'pyodbc', 'yaml', 'cryptography', 'greenlet', 'pyee', 'cffi', 'automation_support',
             'lcs_jit_automation', 'sql_executor'}
    package = name if name in known else 'a required package'
    return {'status': 'failure', 'failed_at_step': 'configuration',
            'error_message': f'Python package {package} is missing or damaged in automation/.venv. Rerun run.cmd to repair the local environment.',
            'diagnostic': {'type': type(error).__name__, 'module': package}, 'screenshot_path': None, 'exit_code': 1}


def runtime_facts() -> dict[str, Any]:
    facts: dict[str, Any] = {'python': platform.python_version(), 'platform': platform.platform(), 'machine': platform.machine()}
    try:
        from importlib.metadata import version
        facts['playwright'] = version('playwright')
    except Exception:
        pass
    return facts


def save_diagnostics(logs_path: Path, command: str, output: dict[str, Any]) -> None:
    """Best effort: a failed write never changes the command result."""
    record = {'command': command, 'created_at': timestamp(utcnow()), 'failed_at_step': output.get('failed_at_step'),
              'error_message': output.get('error_message'), 'diagnostic': output.get('diagnostic', {}), 'runtime': runtime_facts()}
    try:
        folder = logs_path / 'diagnostics'
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f'{command}-{utcnow().strftime("%Y%m%dT%H%M%S%fZ")}.json'
        path.write_text(json.dumps(record, indent=2), encoding='utf-8')
        output['diagnostic_file'] = str(path)
    except OSError:
        output['diagnostic_write_failed'] = True


def write_diagnostic(path: Path, data: dict[str, Any], output: dict[str, Any]) -> None:
    try:
        path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    except OSError:
        # Auxiliary diagnostics must not prevent cleanup or erase its result.
        output['diagnostic_write_failed'] = True


def run(config: Config, log_dir: Path, *, headed: bool = False, interactive_auth: bool = False, scripts: list[PreparedScript] | None = None) -> dict[str, Any]:
    adapter: LCSAutomation | None = None
    credentials: Credentials | None = None
    output: dict[str, Any] = {}
    step = 'authentication'
    started = time.monotonic()
    with sync_playwright() as playwright:
        try:
            adapter = LCSAutomation(config, playwright, log_dir, bootstrap=interactive_auth, headed=headed or interactive_auth)
            if interactive_auth:
                adapter.bootstrap()
                adapter.screenshot('01_login')
            else:
                adapter.navigate(allow_interactive_auth=headed)
            step = 'ip_rule'
            adapter.enable_ip(get_public_ip(config))
            step = 'jit_request'
            credentials = adapter.request_access()
            step = 'sql_connection'
            execution = execute_sql_scripts(credentials, config, scripts)
            output = {
                'status': 'failure' if execution['scripts_failed'] else 'success',
                'jit_request': {
                    'environment_id': config.environment_id,
                    'requested_at': timestamp(credentials.requested_at),
                    'expires_at': timestamp(credentials.expires_at),
                    'access_level': config.access_level,
                },
                'sql_execution': execution,
                'credentials_used': {'username': credentials.username, 'server': credentials.server, 'database': credentials.database},
            }
            if execution['scripts_failed']:
                output.update(failed_at_step='script_execution', error_message='One or more scripts failed. See sanitized sql_execution.details; successful earlier scripts remain committed.', exit_code=1,
                              screenshot_path=adapter.screenshot('error_script_execution'))
        except Exception as error:
            details = describe_error(error)
            diagnostic = {'exception_type': type(error).__name__, **details, 'frames': [
                {'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                for frame in traceback.extract_tb(error.__traceback__) if Path(frame.filename).name in {'main.py', 'lcs_jit_automation.py', 'sql_executor.py', 'automation_support.py'}]}
            if isinstance(error, AutomationError):
                step, message = error.step, error.message
            else:
                step = adapter.step if adapter is not None and step not in {'sql_connection', 'script_execution'} else step
                message = explain_error(error, step)
            output = {'status': 'failure', 'failed_at_step': step, 'error_message': message, 'diagnostic': details,
                      'screenshot_path': adapter.screenshot('error') if adapter is not None else None, 'exit_code': 1}
            write_diagnostic(log_dir / 'diagnostic.json', diagnostic, output)
        finally:
            if adapter is not None:
                try:
                    if config.disable_access_after and adapter.ip_rule_attempted:
                        adapter.disable_ip()
                        output['cleanup'] = {'status': 'success', 'scope': 'source_ip_firewall_rule', 'sql_credentials_revoked': False}
                    else:
                        output['cleanup'] = {'status': 'not_requested' if not config.disable_access_after else 'not_needed'}
                except Exception as cleanup_error:
                    cleanup_detail = {'exception_type': type(cleanup_error).__name__, **describe_error(cleanup_error)}
                    if log_dir is not None:
                        write_diagnostic(log_dir / 'cleanup_diagnostic.json', cleanup_detail, output)
                    if isinstance(cleanup_error, AutomationError):
                        message = cleanup_error.message + ' Remove the automation-owned source IP rule manually if present; SQL credentials may remain valid until expiry.'
                    else:
                        message = 'Could not confirm source IP removal. Remove the host IP manually in LCS. SQL credentials may remain valid until expiry.'
                    output['cleanup'] = {'status': 'failure', 'error_message': message, 'diagnostic': describe_error(cleanup_error)}
                    if output.get('status') == 'success':
                        output.update(status='failure', failed_at_step='cleanup', error_message=output['cleanup']['error_message'], exit_code=1,
                                      screenshot_path=adapter.screenshot('error_cleanup'))
                finally:
                    date_format = getattr(adapter, 'lcs_date_format', '')
                    if isinstance(date_format, str) and date_format:
                        output['lcs_date_format'] = date_format  # How LCS rendered expiry dates on this machine.
                    try:
                        adapter.close()
                    except Exception:
                        output.update(status='failure', failed_at_step='cleanup', error_message='Browser cleanup failed; inspect local Chromium processes.', exit_code=1)
    output['total_execution_time_seconds'] = round(time.monotonic() - started, 3)
    secrets = (os.environ.get('LCS_AUTH_KEY', ''), credentials.password if credentials else '')
    safe_output: dict[str, Any] = scrub(output, secrets)
    if credentials is not None:
        credentials.password = '' # Best effort; Python/ODBC do not guarantee memory zeroization.
    return safe_output


def installed_sql_drivers() -> list[str]:
    try:
        import pyodbc
        return [name for name in pyodbc.drivers() if isinstance(name, str)]
    except Exception:
        raise AutomationError('configuration', 'The pyodbc ODBC module could not load. Rerun run.cmd to repair automation/.venv; if it keeps failing, reinstall Microsoft ODBC Driver 18 for SQL Server (x64).') from None


def check_runtime(config: Config) -> None:
    """Fail locally before requesting firewall/JIT access."""
    installed = installed_sql_drivers()
    if config.odbc_driver not in installed:
        if config.minimal_profile:
            raise AutomationError('configuration', 'Microsoft ODBC Driver 18 or 17 for SQL Server (x64) is not installed. Rerun run.cmd (it installs Driver 18 with administrator approval) or ask IT to install it.')
        found = [name for name in installed if 'SQL Server' in name and re.fullmatch(r'[A-Za-z0-9 ._()-]{1,80}', name)]
        listing = ', '.join(found) if found else 'none'
        raise AutomationError('configuration', f'Configured SQL_ODBC_DRIVER "{config.odbc_driver}" is not installed (installed SQL Server drivers: {listing}). Install it, or change SQL_ODBC_DRIVER in your profile.')
    with sync_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            raise AutomationError('configuration', 'Playwright Chromium is missing. Rerun run.cmd to install it locally.')


def unexpected_step(error: BaseException) -> str:
    browser = str(describe_error(error).get('browser', ''))
    return 'browser_start' if browser in {'executable_missing', 'launch_failed', 'profile_in_use'} else 'configuration'


def main(argv: list[str] | None = None) -> int:
    if _IMPORT_ERROR is not None:
        print(json.dumps(import_failure_report(_IMPORT_ERROR), indent=2))
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=COMMANDS, nargs='?', default='run')
    parser.add_argument('--config', type=Path, default=APP_DIR.parent / 'config.yaml')
    parser.add_argument('--cdp-url', default='http://127.0.0.1:9222', help='Loopback-only Edge debugging URL for import-auth')
    parser.add_argument('--headed', action='store_true', help='Run the browser UI visibly instead of headless')
    parser.add_argument('--interactive-auth', action='store_true', help='Authenticate interactively in the current run browser before continuing')
    parser.add_argument('--check-runtime', action='store_true', help='Also verify installed ODBC driver and Chromium during validate')
    args = parser.parse_args(argv)
    log_dir: Path | None = None
    logs_path: Path | None = None  # Known only once the configuration loaded.
    try:
        config = Config.load(args.config, bootstrap=args.command in {'bootstrap', 'import-auth'})
        logs_path = config.logs_path
        if args.command == 'validate':
            files = validate_scripts(config.scripts_path)
            if args.check_runtime:
                check_runtime(config)
            output: dict[str, Any] = {'status': 'success', 'configuration_valid': True, 'total_scripts': len(files), 'live_lcs_validated': False,
                                      'runtime_checked': args.check_runtime, 'firewall_rule_name': config.selectors.get('rule_name', ''),
                                      'public_ip_source': config.public_ip_source}
        elif args.command == 'check-auth':
            with sync_playwright() as playwright:
                adapter = LCSAutomation(config, playwright, config.logs_path / 'auth_check')
                try:
                    adapter.navigate()
                finally:
                    adapter.close()
            output = {'status': 'success', 'authentication_state': 'valid', 'access_changes': False}
        elif args.command == 'import-auth':
            from urllib.parse import urlsplit
            target = urlsplit(args.cdp_url)
            if target.scheme != 'http' or target.hostname not in {'127.0.0.1', 'localhost', '::1'} or target.username or target.password:
                raise AutomationError('authentication', 'import-auth requires a localhost-only debugging URL.')
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp(args.cdp_url)
                matches = [(context, page) for context in browser.contexts for page in context.pages
                           if urlsplit(page.url).hostname in LCS_HOSTS
                           and urlsplit(page.url).path == f'/V2/EnvironmentDetailsV3New/{config.project_id}']
                if config.environment_url:
                    from urllib.parse import parse_qs
                    matches = [(context, page) for context, page in matches
                               if [v.lower() for v in parse_qs(urlsplit(page.url).query).get('EnvironmentId', [])] == [config.environment_key.lower()]]
                if len(matches) != 1:
                    raise AutomationError('authentication', 'Open exactly one matching LCS environment in the inspection browser.')
                heading = matches[0][1].locator('h1')
                if heading.count() != 1 or not heading.inner_text().strip() or (config.environment_id and heading.inner_text().strip() != config.environment_id):
                    raise AutomationError('environment', 'Inspection browser environment heading does not match the configured environment.')
                save_auth(matches[0][0], config.state_path, config.auth_key_path)
                # Do not close the user's inspection browser; exiting Playwright disconnects.
            output = {'status': 'success', 'authentication_state': 'imported_encrypted'}
        elif args.command == 'bootstrap':
            with sync_playwright() as playwright:
                adapter = LCSAutomation(config, playwright, config.logs_path, bootstrap=True)
                try:
                    adapter.bootstrap()
                finally:
                    adapter.close()
            output = {'status': 'success', 'authentication_state': 'saved_encrypted'}
        else:
            scripts = prepare_scripts(config.scripts_path) # Freeze exact batches before access changes.
            check_runtime(config)
            log_dir = config.logs_path / utcnow().strftime('%Y-%m-%d_%H-%M-%S_%f')
            log_dir.mkdir(parents=True, exist_ok=False)
            with environment_lock(config):
                output = run(config, log_dir, headed=args.headed, interactive_auth=args.interactive_auth, scripts=scripts)
    except Exception as error:
        output = {'status': 'failure', 'failed_at_step': error.step if isinstance(error, AutomationError) else unexpected_step(error),
                  'error_message': error.message if isinstance(error, AutomationError) else explain_error(error, args.command),
                  'diagnostic': describe_error(error), 'screenshot_path': None, 'exit_code': 1}
    output = scrub(output, (os.environ.get('LCS_AUTH_KEY', ''),))
    if output.get('status') == 'failure':
        if not output.get('screenshot_path'):
            output['screenshot_note'] = 'Browser state unavailable or safe masking failed; no unmasked image was written.'
        if logs_path is not None:
            save_diagnostics(logs_path, args.command, output)
    encoded = json.dumps(output, indent=2, allow_nan=False)
    if log_dir is not None:
        try:
            (log_dir / 'report.json').write_text(encoded + '\n', encoding='utf-8')
        except OSError:
            output.update(status='failure', failed_at_step='audit_log', error_message='Could not write audit report. Check log directory permissions.', exit_code=1)
            encoded = json.dumps(output, indent=2, allow_nan=False)
    print(encoded)
    return 0 if output['status'] == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
