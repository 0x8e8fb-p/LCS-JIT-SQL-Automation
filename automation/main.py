"""CLI for the config.yaml / run.ps1 LCS JIT workflow."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from playwright.sync_api import sync_playwright

from automation_support import AutomationError, Config, Credentials, environment_lock, timestamp, utcnow
from lcs_jit_automation import LCSAutomation, get_public_ip, save_auth
from sql_executor import execute_sql_scripts, scrub, validate_scripts


def run(config: Config, log_dir: Path, *, headed: bool = False) -> dict[str, Any]:
    adapter: LCSAutomation | None = None
    credentials: Credentials | None = None
    output: dict[str, Any] = {}
    step = 'authentication'
    started = time.monotonic()
    with sync_playwright() as playwright:
        try:
            adapter = LCSAutomation(config, playwright, log_dir, headed=headed)
            adapter.navigate()
            step = 'ip_rule'
            adapter.enable_ip(get_public_ip(config))
            step = 'jit_request'
            credentials = adapter.request_access()
            step = 'sql_connection'
            execution = execute_sql_scripts(credentials, config)
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
            diagnostic = {'exception_type': type(error).__name__, 'frames': [
                {'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                for frame in traceback.extract_tb(error.__traceback__) if Path(frame.filename).name in {'main.py', 'lcs_jit_automation.py', 'sql_executor.py', 'automation_support.py'}]}
            (log_dir / 'diagnostic.json').write_text(json.dumps(diagnostic, indent=2), encoding='utf-8')
            if isinstance(error, AutomationError):
                step, message = error.step, error.message
            else:
                step = adapter.step if adapter is not None and step not in {'sql_connection', 'script_execution'} else step
                message = 'Automation failed. Check installed browser/ODBC dependencies, authentication, configured selectors, and network connectivity; raw exception suppressed for security.'
            output = {'status': 'failure', 'failed_at_step': step, 'error_message': message,
                      'screenshot_path': adapter.screenshot('error') if adapter is not None else None, 'exit_code': 1}
        finally:
            if adapter is not None:
                try:
                    if config.disable_access_after and adapter.ip_rule_attempted:
                        adapter.disable_ip()
                        output['cleanup'] = {'status': 'success', 'scope': 'source_ip_firewall_rule', 'sql_credentials_revoked': False}
                    else:
                        output['cleanup'] = {'status': 'not_requested' if not config.disable_access_after else 'not_needed'}
                except Exception as cleanup_error:
                    cleanup_detail = {'exception_type': type(cleanup_error).__name__}
                    if log_dir is not None:
                        (log_dir / 'cleanup_diagnostic.json').write_text(json.dumps(cleanup_detail, indent=2), encoding='utf-8')
                    if isinstance(cleanup_error, AutomationError):
                        message = cleanup_error.message + ' Remove the automation-owned source IP rule manually if present; SQL credentials may remain valid until expiry.'
                    else:
                        message = 'Could not confirm source IP removal. Remove the host IP manually in LCS. SQL credentials may remain valid until expiry.'
                    output['cleanup'] = {'status': 'failure', 'error_message': message}
                    if output.get('status') == 'success':
                        output.update(status='failure', failed_at_step='cleanup', error_message=output['cleanup']['error_message'], exit_code=1,
                                      screenshot_path=adapter.screenshot('error_cleanup'))
                finally:
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


def check_runtime(config: Config) -> None:
    """Fail locally before requesting firewall/JIT access."""
    import pyodbc
    if config.odbc_driver not in pyodbc.drivers():
        raise AutomationError('configuration', 'Configured SQL_ODBC_DRIVER is not installed. Install Microsoft ODBC Driver 17/18 or select an installed supported driver in config.yaml; pip cannot install it.')
    with sync_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            raise AutomationError('configuration', 'Playwright Chromium is missing. Run ./run.ps1 to install it locally.')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['run', 'bootstrap', 'import-auth', 'validate', 'check-auth'], nargs='?', default='run')
    parser.add_argument('--config', type=Path, default=Path(__file__).resolve().parent.parent / 'config.yaml')
    parser.add_argument('--cdp-url', default='http://127.0.0.1:9222', help='Loopback-only Edge debugging URL for import-auth')
    parser.add_argument('--headed', action='store_true', help='Run the browser UI visibly instead of headless')
    parser.add_argument('--check-runtime', action='store_true', help='Also verify installed ODBC driver and Chromium during validate')
    args = parser.parse_args(argv)
    log_dir: Path | None = None
    try:
        config = Config.load(args.config, bootstrap=args.command in {'bootstrap', 'import-auth'})
        if args.command == 'validate':
            files = validate_scripts(config.scripts_path)
            if args.check_runtime:
                check_runtime(config)
            output: dict[str, Any] = {'status': 'success', 'configuration_valid': True, 'total_scripts': len(files), 'live_lcs_validated': False,
                                      'runtime_checked': args.check_runtime}
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
                           if urlsplit(page.url).hostname == 'lcs.dynamics.com'
                           and urlsplit(page.url).path == f'/V2/EnvironmentDetailsV3New/{config.project_id}']
                if config.environment_url:
                    from urllib.parse import parse_qs
                    matches = [(context, page) for context, page in matches
                               if parse_qs(urlsplit(page.url).query).get('EnvironmentId') == [config.environment_key]]
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
            validate_scripts(config.scripts_path) # Read and parse before any access changes.
            check_runtime(config)
            log_dir = config.logs_path / utcnow().strftime('%Y-%m-%d_%H-%M-%S_%f')
            log_dir.mkdir(parents=True, exist_ok=False)
            with environment_lock(config):
                output = run(config, log_dir, headed=args.headed)
    except Exception as error:
        output = {'status': 'failure', 'failed_at_step': error.step if isinstance(error, AutomationError) else 'configuration',
                  'error_message': error.message if isinstance(error, AutomationError) else 'Startup failed. Verify local dependencies, configuration, and file permissions; raw error suppressed.',
                  'screenshot_path': None, 'exit_code': 1}
    output = scrub(output, (os.environ.get('LCS_AUTH_KEY', ''),))
    if output.get('status') == 'failure' and not output.get('screenshot_path'):
        output['screenshot_note'] = 'Browser state unavailable or safe masking failed; no unmasked image was written.'
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
