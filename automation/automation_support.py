"""Shared contracts. Never format untrusted browser/ODBC exceptions into output."""
from __future__ import annotations

import ipaddress
import os
import hashlib
import sys
from contextlib import contextmanager
from collections.abc import Iterator
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import parse_qs, urlsplit
import uuid

import yaml


class ConfigProblem(ValueError):
    """One author-written, secret-free configuration problem (never a raw value)."""


def printable_key(key: object) -> str:
    text = str(key)
    return text if re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', text) else '(unprintable key)'


class UniqueKeyLoader(yaml.SafeLoader):
    """YAML duplicate keys are errors, not silent last-value-wins overrides."""
    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise ConfigProblem(f'duplicate key {printable_key(key)} on line {key_node.start_mark.line + 1} (keep only one)')
            seen.add(key)
        return dict(super().construct_mapping(node, deep=deep))


class AutomationError(Exception):
    def __init__(self, step: str, message: str):
        super().__init__(message)
        self.step = step
        self.message = message


# --- Safe diagnostics -------------------------------------------------------
# Raw browser, ODBC, OS and YAML messages can contain URLs, SQL text, user names
# or passwords. Diagnostics therefore carry only class names, numeric codes and
# fixed categories derived from the message, never the message itself.
_SAFE_NAME = re.compile(r'[A-Za-z0-9 ._()+-]{1,80}')
_NET_ERROR = re.compile(r'net::ERR_[A-Z0-9_]{2,60}')
_BROWSER_PATTERNS = (
    ('executable_missing', re.compile(r"Executable doesn't exist|Looks like Playwright|playwright install", re.I)),
    ('profile_in_use', re.compile(r'ProcessSingleton|SingletonLock|profile (?:appears to be )?in use|user data directory is already in use', re.I)),
    ('browser_closed', re.compile(r'has been closed|Target closed|Browser closed', re.I)),
    ('timeout', re.compile(r'Timeout \d+ ?ms exceeded', re.I)),
    ('launch_failed', re.compile(r'Failed to launch|spawn \S+ (?:EACCES|EPERM|UNKNOWN|ENOENT)|exitCode=', re.I)),
)
PACKAGE_MODULES = {'playwright', 'pyodbc', 'yaml', 'cryptography', 'greenlet', 'pyee', 'cffi', '_cffi_backend'}


def error_chain(error: BaseException, limit: int = 3) -> list[BaseException]:
    """The error plus up to two causes, including contexts hidden by 'from None'."""
    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and len(chain) < limit and all(current is not seen for seen in chain):
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def safe_file_name(value: object) -> str:
    name = PureWindowsPath(str(value)).name
    return name if _SAFE_NAME.fullmatch(name) else '<file>'


def browser_category(error: BaseException) -> str | None:
    """Fixed category for a Playwright error; None for other exception types."""
    if not type(error).__module__.startswith('playwright'):
        return None
    text = str(error)
    network = _NET_ERROR.search(text)
    if network:
        return network.group(0)
    if type(error).__name__ == 'TimeoutError':
        return 'timeout'
    for category, pattern in _BROWSER_PATTERNS:
        if pattern.search(text):
            return category
    return 'other'


def odbc_codes(error: BaseException) -> dict[str, Any] | None:
    """SQLSTATE and native error numbers of a pyodbc error (digits only)."""
    if type(error).__module__.split('.')[0] != 'pyodbc':
        return None
    state = str(error.args[0]) if error.args else ''
    codes: dict[str, Any] = {'sqlstate': state if re.fullmatch(r'[A-Z0-9]{5}', state) else 'unknown'}
    natives = sorted({int(number) for argument in error.args[1:] for number in re.findall(r'\((\d{1,6})\)', str(argument))})
    if natives:
        codes['native'] = natives[:5]
    return codes


def describe_error(error: BaseException) -> dict[str, Any]:
    """Secret-free description: class names, OS/ODBC codes, browser category."""
    chain = error_chain(error)
    info: dict[str, Any] = {'type': type(error).__name__}
    if len(chain) > 1:
        info['causes'] = [type(item).__name__ for item in chain[1:]]
    for item in chain:
        if isinstance(item, OSError):
            if item.errno is not None:
                info.setdefault('errno', item.errno)
            winerror = getattr(item, 'winerror', None)
            if winerror:
                info.setdefault('winerror', winerror)
            if item.filename:
                info.setdefault('file', safe_file_name(item.filename))
        if isinstance(item, ImportError) and item.name and re.fullmatch(r'[A-Za-z0-9_.]{1,60}', item.name):
            info.setdefault('module', item.name)
        category = browser_category(item)
        if category:
            info.setdefault('browser', category)
        codes = odbc_codes(item)
        if codes:
            info.setdefault('odbc', codes)
    return info


def explain_error(error: BaseException, step: str) -> str:
    """Actionable message for an unexpected (non-AutomationError) failure."""
    info = describe_error(error)
    chain = error_chain(error)
    module = str(info.get('module', ''))
    if any(isinstance(item, ImportError) for item in chain):
        name = module.split('.')[0] if module.split('.')[0] in PACKAGE_MODULES else 'a required package'
        return f'Python package {name} is missing or damaged in automation/.venv. Rerun run.cmd to repair the local environment.'
    browser = str(info.get('browser', ''))
    if browser.startswith('net::ERR_'):
        return f'Network error {browser} while the browser loaded LCS during {step}. Check Internet, VPN and proxy access to LCS and Microsoft sign-in.'
    messages = {
        'executable_missing': 'Playwright Chromium is missing or incomplete. Rerun run.cmd to reinstall it.',
        'profile_in_use': 'The saved browser profile is in use by another Chromium window. Close browser windows opened by this tool (or end chrome.exe processes started from automation/browsers) and retry.',
        'browser_closed': f'The automation browser closed before {step} finished. Keep its window open until the run ends; if it closes by itself, check security software.',
        'launch_failed': 'Chromium could not start. Security software or application control may be blocking automation/browsers; ask IT to allow it, or rerun run.cmd to reinstall Chromium.',
        'timeout': f'LCS did not respond in time during {step}. Retry; if it keeps happening, check VPN/proxy speed and that LCS opens in a normal browser.',
    }
    if browser in messages:
        return messages[browser]
    if browser:
        return f'Browser automation failed during {step} ({info["type"]}). Retry; the safe diagnostic in automation/logs/diagnostics shows the category.'
    if any(isinstance(item, EOFError) for item in chain):
        return 'Sign-in needs an interactive console. Run run.cmd from PowerShell or Windows Terminal once; -Headless runs reuse that login.'
    if 'odbc' in info:
        codes = info['odbc']
        native = ', native ' + ', '.join(str(number) for number in codes.get('native', [])) if codes.get('native') else ''
        return f'ODBC error (SQLSTATE {codes["sqlstate"]}{native}) during {step}. See README.md#troubleshooting.'
    os_error = next((item for item in chain if isinstance(item, OSError)), None)
    if os_error is not None:
        code = info.get('winerror') or info.get('errno') or 'unknown'
        target = f' on {info["file"]}' if 'file' in info else ''
        return f'File system error {code}{target} during {step}. Check folder permissions, antivirus or OneDrive locks, and free disk space.'
    return f'Unexpected {info["type"]} during {step}. A safe diagnostic was saved under automation/logs/diagnostics; see README.md#troubleshooting.'


@contextmanager
def environment_lock(config: Config) -> Iterator[None]:
    """Nonblocking OS lock, released even after process termination."""
    identity = hashlib.sha256(f'{config.project_id}:{config.environment_key}'.encode()).hexdigest()[:24]
    try:
        config.logs_path.mkdir(parents=True, exist_ok=True)
        handle = (config.logs_path / f'.run-{identity}.lock').open('a+b')
    except OSError:
        raise AutomationError('configuration', 'Cannot create the run lock. Check LOGS_PATH permissions.') from None
    try:
        if handle.seek(0, 2) == 0:
            handle.write(b'0')
            handle.flush()
        handle.seek(0)
        try:
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise AutomationError('configuration', 'Another run is active for this environment. Wait for it to finish; overlapping access changes are refused.') from None
        yield
    finally:
        handle.close() # Closing releases the OS lock; do not unlink a locked inode.


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def parse_expiry(value: str) -> datetime:
    try:
        expiry = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
        if expiry.tzinfo is None:
            raise ValueError('timezone required')
        return expiry.astimezone(timezone.utc)
    except ValueError:
        raise AutomationError('jit_request', 'Expiry must be ISO-8601 with an explicit timezone; calibrate expires_at selector.') from None


@dataclass(repr=False)
class Credentials:
    server: str
    database: str
    username: str
    password: str = field(repr=False)
    requested_at: datetime
    expires_at: datetime

    def ensure_valid(self, step: str = 'script_execution') -> None:
        if utcnow() >= self.expires_at:
            raise AutomationError(step, 'JIT access expired. Bootstrap authentication if needed, then request new access; no scripts were automatically replayed.')

    def __repr__(self) -> str:
        return 'Credentials(<redacted>)'


def parse_server_database(value: str, suffix: str) -> tuple[str, str]:
    parts = value.strip().split('\\')
    if len(parts) != 2 or not all(parts):
        raise AutomationError('jit_request', 'Expected exactly server\\database in the credential row.')
    server, database = parts
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', server):
        raise AutomationError('jit_request', 'SQL server field is not a valid DNS hostname.')
    if '.' not in server:
        server = f'{server}.{suffix}'
    if not server.lower().endswith('.' + suffix.lower()):
        raise AutomationError('jit_request', 'SQL server does not match the configured Azure SQL DNS suffix.')
    return server, database


LCS_HOSTS = {
    'lcs.dynamics.com',
    'eu.lcs.dynamics.com',
    'fr.lcs.dynamics.com',
    'sa.lcs.dynamics.com',
    'uae.lcs.dynamics.com',
    'ch.lcs.dynamics.com',
    'no.lcs.dynamics.com',
}
BOOL_KEYS = {'CONTINUE_ON_ERROR', 'DISABLE_ACCESS_AFTER'}
ENV_KEYS = {
    'LCS_PROJECT_ID', 'ENVIRONMENT_ID', 'ACCESS_LEVEL', 'ACCESS_REASON',
    'ACCESS_DETAILS', 'SQL_SCRIPTS_PATH', 'STORAGE_STATE_PATH', 'LOGS_PATH',
    'PUBLIC_IP', 'SQL_DNS_SUFFIX', 'SQL_TIMEOUT_SECONDS', 'MAX_RESULT_ROWS',
    'ENVIRONMENT_URL', 'BROWSER_TIMEZONE', 'SQL_ODBC_DRIVER', 'AUTH_KEY_PATH',
    'FIREWALL_RULE_NAME',
} | BOOL_KEYS


@dataclass
class Config:
    project_id: str
    environment_id: str
    access_level: str
    reason: str
    details: str
    scripts_path: Path
    state_path: Path
    logs_path: Path
    continue_on_error: bool
    disable_access_after: bool
    public_ip: str
    sql_dns_suffix: str
    sql_timeout: int
    max_result_rows: int
    selectors: dict[str, str]
    environment_url: str = ''
    browser_timezone: str = 'UTC'
    odbc_driver: str = 'ODBC Driver 18 for SQL Server'
    auth_key_path: Path | None = None
    minimal_profile: bool = False

    @property
    def lcs_origin(self) -> str:
        if self.environment_url:
            target = urlsplit(self.environment_url)
            if target.scheme == 'https' and target.netloc in LCS_HOSTS:
                return f'{target.scheme}://{target.netloc}'
        return 'https://lcs.dynamics.com'

    @property
    def environment_key(self) -> str:
        return parse_qs(urlsplit(self.environment_url).query).get('EnvironmentId', [self.environment_id])[0]

    @classmethod
    def load(cls, path: Path, *, bootstrap: bool = False) -> Config:
        """Load and validate a profile, reporting every independent problem at once."""
        try:
            return cls._load(path, bootstrap)
        except ConfigProblems as problems:
            items = problems.items
            listed = items[0] if len(items) == 1 else ' '.join(f'({number}) {item};' for number, item in enumerate(items, 1)).rstrip(';')
            raise AutomationError('configuration', f'Invalid configuration: {listed}. See README.md#configuration.') from None
        except ConfigProblem as problem:
            raise AutomationError('configuration', f'Invalid configuration: {problem}. See README.md#configuration.') from None
        except (OSError, ValueError, TypeError, yaml.YAMLError):
            # Raw parser/OS errors may quote secret-bearing config lines; never show them.
            raise AutomationError('configuration', 'Invalid configuration. Paste a complete HTTPS LCS environment URL, an exact supported ACCESS_REASON, non-empty ACCESS_DETAILS, and a valid FIREWALL_RULE_NAME. Remove duplicate YAML keys/stale advanced environment overrides. See README.md#configuration for the fields and README.md#advanced-profiles for profiles.') from None

    @classmethod
    def _load(cls, path: Path, bootstrap: bool) -> Config:
        name = safe_file_name(path)
        raw = read_profile(path)
        problems: list[str] = []
        data: dict[str, Any] = {}
        for key, value in raw.items():
            if not isinstance(key, str):
                problems.append(f'setting names must be text ({printable_key(key)} is not)')
                continue
            data[key] = value.strip() if isinstance(value, str) else value
        minimal = 'selectors' not in data
        if minimal:
            unknown = sorted(printable_key(key) for key in set(data) - MINIMAL_KEYS)
            if unknown:
                problems.append(f'unknown setting(s) {", ".join(unknown)} in {name} (config.yaml accepts only '
                                f'{", ".join(sorted(MINIMAL_KEYS))}, advanced settings need a profile with selectors: README.md#advanced-profiles)')
            conflicting = sorted(key for key in ENV_KEYS - MINIMAL_KEYS if key in os.environ)
            if conflicting:
                removal = '; '.join(f'Remove-Item Env:{key}' for key in conflicting)
                problems.append(f'environment variable(s) {", ".join(conflicting)} would override config.yaml (Windows matches names in any letter case), remove them '
                                f'for this window with {removal} and permanently in System Properties > Environment Variables')
            overrides = MINIMAL_KEYS
        else:
            unknown = sorted(printable_key(key) for key in data if key not in ENV_KEYS | {'selectors'})
            if unknown:
                problems.append(f'unknown setting(s) {", ".join(unknown)} (check spelling against automation/config.advanced.yaml)')
            overrides = ENV_KEYS
        for key in overrides:
            if key in os.environ:
                data[key] = os.environ[key].strip()
        if minimal:
            if 'FIREWALL_RULE_NAME' not in data:
                problems.append('FIREWALL_RULE_NAME is missing')
            defaults = yaml.safe_load(Path(__file__).with_name('defaults.yaml').read_text(encoding='utf-8'))
            data = {**defaults, **data}

        def text(key: str, default: str = '') -> str:
            value = data.get(key, default)
            if value is None:
                return ''
            if not isinstance(value, str):
                problems.append(f'{key} must be a quoted text value')
                return default
            return value.strip()

        def boolean(key: str, default: bool) -> bool:
            value = data.get(key, default)
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in {'true', 'false'}:
                return value.lower() == 'true'
            problems.append(f'{key} must be true or false')
            return default

        def positive(key: str, default: int, maximum: int) -> int:
            value = data.get(key, default)
            try:
                if isinstance(value, bool):
                    raise ValueError('boolean')
                number = int(value)
                if str(number) != str(value).strip() or not 1 <= number <= maximum:
                    raise ValueError('range')
                return number
            except (TypeError, ValueError):
                problems.append(f'{key} must be a whole number between 1 and {maximum}')
                return default

        environment_url = text('ENVIRONMENT_URL')
        url_valid = False
        if environment_url:
            url_problems, derived_project, environment_guid = check_environment_url(environment_url)
            problems.extend(url_problems)
            if not url_problems:
                url_valid = True
                if 'LCS_PROJECT_ID' in data and str(data['LCS_PROJECT_ID']).strip() != derived_project:
                    problems.append('LCS_PROJECT_ID does not match the project number in ENVIRONMENT_URL')
                data['LCS_PROJECT_ID'] = derived_project
                # Heading is read from this verified URL when no name was supplied.
                data.setdefault('ENVIRONMENT_ID', '')
                identity = hashlib.sha256(f'{derived_project}:{environment_guid}'.encode()).hexdigest()[:24]
                data.setdefault('STORAGE_STATE_PATH', str(Path(__file__).parent / '.auth' / f'{identity}.enc'))
                if os.name == 'nt':
                    data.setdefault('AUTH_KEY_PATH', str(Path(__file__).parent / '.auth' / f'{identity}.dpapi'))
                data.setdefault('LOGS_PATH', str(Path(__file__).parent / 'logs'))
        reason = text('ACCESS_REASON')
        details = text('ACCESS_DETAILS')
        level = text('ACCESS_LEVEL') if 'ACCESS_LEVEL' in data else SUPPORTED_REASONS.get(reason, '')
        reason_labels = '; '.join(f'"{label}"' for label in SUPPORTED_REASONS)
        if not reason or reason.startswith('REPLACE_'):
            if not bootstrap:
                problems.append(f'ACCESS_REASON is empty or a placeholder, set it to the exact LCS reason, one of: {reason_labels}')
        elif 'ACCESS_LEVEL' not in data and reason not in SUPPORTED_REASONS:
            problems.append(f'ACCESS_REASON must be exactly one of the LCS reasons: {reason_labels}')
        base = path.resolve().parent

        def local_path(key: str, default: str) -> Path:
            return (base / (text(key, default) or default)).resolve()

        project = text('LCS_PROJECT_ID')
        environment = text('ENVIRONMENT_ID')
        if not environment_url and not environment:
            problems.append('ENVIRONMENT_URL is empty (paste the complete LCS environment-details URL from the browser address bar, it contains EnvironmentId=)')
        elif not url_valid and not environment_url and not project.isdigit():
            problems.append('LCS_PROJECT_ID must be the numeric LCS project ID')
        if ('ACCESS_LEVEL' in data or level) and level not in {'read_only', 'read_write'}:
            problems.append('ACCESS_LEVEL must be read_only or read_write')
        if not bootstrap and not details:
            problems.append('ACCESS_DETAILS is empty (enter the approved justification for the LCS request)')
        raw_selectors = data.get('selectors', {})
        selectors: dict[str, str] = {}
        if not isinstance(raw_selectors, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in raw_selectors.items()):
            problems.append('selectors must map names to quoted CSS selector text')
        else:
            unknown_selectors = sorted(printable_key(key) for key in raw_selectors if key not in SELECTOR_KEYS)
            if unknown_selectors:
                problems.append(f'unknown selector(s) {", ".join(unknown_selectors)} (check spelling)')
            selectors = {key: value.strip() for key, value in raw_selectors.items()}
        if reason in READ_ONLY_REASONS and level and level != 'read_only':
            problems.append('the selected ACCESS_REASON grants read-only access, so ACCESS_LEVEL must be read_only')
        if reason in READ_WRITE_REASONS and level and level != 'read_write':
            problems.append('the selected ACCESS_REASON grants write access, so ACCESS_LEVEL must be read_write')
        if 'FIREWALL_RULE_NAME' in data:
            rule_name = text('FIREWALL_RULE_NAME')
            if not RULE_NAME.fullmatch(rule_name):
                problems.append('FIREWALL_RULE_NAME must be 1-64 letters, digits, underscores or hyphens, starting with a letter or digit')
            selectors['rule_name'] = rule_name
        if selectors.get('expiry_format', '') not in {'', 'iso8601', 'lcs_utc'}:
            problems.append('selectors.expiry_format must be iso8601 or lcs_utc')
        disable = boolean('DISABLE_ACCESS_AFTER', True)
        required = ['accounts', 'rows', 'server_database', 'username', 'password', 'expires_at']
        if disable and not selectors.get('rule_grid'):
            required.append('disable_ip_address')
        if selectors.get('rule_grid'):
            required += ['enable_dialog', 'rule_add', 'rule_close', 'rule_add_dialog', 'rule_confirm']
            if disable:
                required.append('rule_delete')
        missing = [key for key in required if not selectors.get(key)]
        if not bootstrap and missing:
            problems.append('calibrate the required selector(s) ' + ', '.join(missing))
        ip = text('PUBLIC_IP')
        if ip:
            try:
                address = ipaddress.ip_address(ip)
                if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
                    raise ValueError('not global IPv4')
            except ValueError:
                problems.append('PUBLIC_IP must be the public IPv4 address your SQL traffic leaves from, such as 203.0.113.10')
        suffix = text('SQL_DNS_SUFFIX', 'database.windows.net') or 'database.windows.net'
        if not re.fullmatch(r'[A-Za-z0-9]+(?:\.[A-Za-z0-9-]+)+', suffix):
            problems.append('SQL_DNS_SUFFIX must be a DNS suffix such as database.windows.net')
        if environment_url and url_valid and urlsplit(environment_url).path != f'/V2/EnvironmentDetailsV3New/{project}':
            problems.append('ENVIRONMENT_URL must target the configured LCS project')
        timezone_name = text('BROWSER_TIMEZONE', 'UTC') or 'UTC'
        if timezone_name != 'UTC':
            problems.append('BROWSER_TIMEZONE must be UTC (the only verified setting)')
        try:
            import pyodbc
            installed = list(pyodbc.drivers())
        except Exception:
            installed = [] # A broken pyodbc is reported by check_runtime, not as a config error.
        auto_driver = next((driver_name for driver_name in SUPPORTED_DRIVERS if driver_name in installed), SUPPORTED_DRIVERS[0])
        driver = text('SQL_ODBC_DRIVER', auto_driver) or auto_driver
        if driver not in SUPPORTED_DRIVERS:
            problems.append('SQL_ODBC_DRIVER must be "ODBC Driver 18 for SQL Server" or "ODBC Driver 17 for SQL Server"')
        state_path = local_path('STORAGE_STATE_PATH', './.auth/lcs_auth.enc')
        key_path = local_path('AUTH_KEY_PATH', '') if text('AUTH_KEY_PATH') else None
        if key_path == state_path:
            problems.append('AUTH_KEY_PATH and STORAGE_STATE_PATH must be different files')
        continue_on_error = boolean('CONTINUE_ON_ERROR', False)
        sql_timeout = positive('SQL_TIMEOUT_SECONDS', 60, 3600)
        max_rows = positive('MAX_RESULT_ROWS', 100, 10000)
        if problems:
            raise ConfigProblems(list(dict.fromkeys(problems)))
        return cls(project, environment, level or 'read_only', reason, details,
                   local_path('SQL_SCRIPTS_PATH', './sql_scripts'),
                   state_path,
                   local_path('LOGS_PATH', './logs'),
                   continue_on_error, disable, ip, suffix, sql_timeout, max_rows, dict(selectors),
                   environment_url, timezone_name, driver,
                   key_path, minimal)


class ConfigProblems(ValueError):
    def __init__(self, items: list[str]):
        super().__init__('; '.join(items))
        self.items = items


MINIMAL_KEYS = {'ENVIRONMENT_URL', 'ACCESS_REASON', 'ACCESS_DETAILS', 'FIREWALL_RULE_NAME'}
SUPPORTED_REASONS = {
    'AX troubleshooting (read-only to AX)': 'read_only',
    'MR troubleshooting (read-only to MR)': 'read_only',
    'Performance tuning for AX (write to AX)': 'read_write',
    'Troubleshooting and tuning entity store (write to AXDW)': 'read_write',
}
READ_ONLY_REASONS = {label for label, level in SUPPORTED_REASONS.items() if level == 'read_only'}
READ_WRITE_REASONS = {label for label, level in SUPPORTED_REASONS.items() if level == 'read_write'}
SUPPORTED_DRIVERS = ('ODBC Driver 18 for SQL Server', 'ODBC Driver 17 for SQL Server')
RULE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
SELECTOR_KEYS = {
    'environment_link', 'maintain', 'enable_access', 'enable_dialog', 'ip_address',
    'enable_submit', 'accounts', 'reason', 'reason_list', 'details', 'request_access',
    'rows', 'server_database', 'username', 'password', 'password_reveal', 'expires_at',
    'expiry_format', 'row_reason', 'row_details', 'disable_access', 'disable_dialog',
    'disable_ip_address', 'disable_submit', 'rule_name', 'rule_grid', 'rule_add',
    'rule_delete', 'rule_close', 'rule_add_dialog', 'rule_confirm',
}


def read_profile(path: Path) -> dict[Any, Any]:
    """Read a YAML mapping; file-level problems are fatal and described safely."""
    name = safe_file_name(path)
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        raise ConfigProblem(f'{name} was not found') from None
    except OSError as error:
        code = getattr(error, 'winerror', None) or error.errno or 'unknown'
        raise ConfigProblem(f'{name} cannot be read (error {code}): check permissions and that it is not locked or still syncing') from None
    if content.startswith((b'\xff\xfe', b'\xfe\xff')):
        raise ConfigProblem(f'{name} is saved as UTF-16, save it as UTF-8 (Notepad: Save as > Encoding: UTF-8)')
    try:
        decoded = content.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ConfigProblem(f'{name} is not UTF-8 text, save it as UTF-8 (Notepad: Save as > Encoding: UTF-8)') from None
    try:
        raw = yaml.load(decoded, Loader=UniqueKeyLoader)
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark or error.context_mark
        where = f' near line {mark.line + 1}, column {mark.column + 1}' if mark is not None else ''
        raise ConfigProblem(f'{name} is not valid YAML{where} (check quotes, colons and indentation)') from None
    except yaml.YAMLError:
        raise ConfigProblem(f'{name} is not valid YAML (check quotes, colons and indentation)') from None
    if not isinstance(raw, dict):
        raise ConfigProblem(f'{name} must contain "KEY: value" lines such as ENVIRONMENT_URL: "https://..."')
    return raw


def check_environment_url(url: str) -> tuple[list[str], str, str]:
    """Problems with an LCS environment-details URL, plus its project and GUID."""
    problems: list[str] = []
    try:
        target = urlsplit(url)
    except ValueError:
        return ['ENVIRONMENT_URL is not a valid URL; copy it from the browser address bar'], '', ''
    if target.scheme != 'https':
        problems.append('ENVIRONMENT_URL must start with https://')
    if target.netloc not in LCS_HOSTS:
        host = target.hostname or ''
        shown = f' ({host})' if re.fullmatch(r'[A-Za-z0-9.-]{1,100}', host) else ''
        problems.append(f'ENVIRONMENT_URL host{shown} is not an LCS host (use lcs.dynamics.com or your regional LCS host such as eu.lcs.dynamics.com)')
    match = re.fullmatch(r'/V2/EnvironmentDetailsV3New/(\d+)', target.path)
    if not match:
        problems.append('ENVIRONMENT_URL must be the environment-details page (/V2/EnvironmentDetailsV3New/<project number>), not the project or application URL')
    if target.fragment:
        problems.append('ENVIRONMENT_URL must not contain a #fragment')
    ids = parse_qs(target.query, keep_blank_values=True).get('EnvironmentId', [])
    guid = ''
    if not ids:
        problems.append('ENVIRONMENT_URL is missing ?EnvironmentId=<GUID> (copy the complete address)')
    elif len(ids) > 1:
        problems.append('ENVIRONMENT_URL contains EnvironmentId more than once')
    else:
        try:
            canonical = str(uuid.UUID(ids[0])).lower()
        except ValueError:
            problems.append('EnvironmentId in ENVIRONMENT_URL is not a valid GUID')
        else:
            if ids[0] != canonical:
                problems.append('EnvironmentId must be the lowercase GUID with hyphens exactly as LCS shows it')
            guid = canonical
    return problems, match.group(1) if match else '', guid
