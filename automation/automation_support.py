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


class UniqueKeyLoader(yaml.SafeLoader):
    """YAML duplicate keys are errors, not silent last-value-wins overrides."""
    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if len(set(keys)) != len(keys):
            raise ValueError('Duplicate YAML key')
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
        try:
            raw = yaml.load(path.read_text(encoding='utf-8-sig'), Loader=UniqueKeyLoader)
            if not isinstance(raw, dict):
                raise ValueError('mapping required')
            data: dict[str, Any] = {key: value.strip() if isinstance(value, str) else value for key, value in raw.items()}
            minimal_keys = {'ENVIRONMENT_URL', 'ACCESS_REASON', 'ACCESS_DETAILS', 'FIREWALL_RULE_NAME'}
            minimal = 'selectors' not in data
            if minimal:
                if set(data) - minimal_keys or any(key in os.environ for key in ENV_KEYS - minimal_keys):
                    raise ValueError('Advanced settings require an explicit selectors profile; remove stale environment overrides')
            for key in ENV_KEYS:
                if key in os.environ:
                    data[key] = os.environ[key].strip()
            # URL-only profiles receive internal defaults; explicit legacy profiles
            # with selectors keep their existing behavior for calibrated overrides.
            if data.get('ENVIRONMENT_URL') and 'selectors' not in data:
                if 'FIREWALL_RULE_NAME' not in data:
                    raise ValueError('FIREWALL_RULE_NAME is required in the minimal profile')
                defaults = yaml.safe_load(Path(__file__).with_name('defaults.yaml').read_text(encoding='utf-8'))
                data = {**defaults, **data}
            if data.get('ENVIRONMENT_URL'):
                target = urlsplit(str(data['ENVIRONMENT_URL']))
                match = re.fullmatch(r'/V2/EnvironmentDetailsV3New/(\d+)', target.path)
                ids = parse_qs(target.query, keep_blank_values=True).get('EnvironmentId', [])
                if target.scheme != 'https' or target.netloc not in LCS_HOSTS or target.fragment or not match or len(ids) != 1:
                    raise ValueError('Paste a complete HTTPS LCS environment-details URL')
                try:
                    canonical_id = str(uuid.UUID(ids[0])).lower()
                except ValueError:
                    raise ValueError('EnvironmentId must be a valid GUID') from None
                if ids[0].lower() != canonical_id or ids[0] != canonical_id:
                    raise ValueError('EnvironmentId must be a canonical lowercase GUID')
                derived_project = match.group(1)
                if 'LCS_PROJECT_ID' in data and data['LCS_PROJECT_ID'] != derived_project:
                    raise ValueError('LCS_PROJECT_ID conflicts with ENVIRONMENT_URL')
                data['LCS_PROJECT_ID'] = derived_project
                # Heading is read from this verified URL when no name was supplied.
                data.setdefault('ENVIRONMENT_ID', '')
                identity = hashlib.sha256(f'{derived_project}:{ids[0]}'.encode()).hexdigest()[:24]
                data.setdefault('STORAGE_STATE_PATH', str(Path(__file__).parent / '.auth' / f'{identity}.enc'))
                if os.name == 'nt':
                    data.setdefault('AUTH_KEY_PATH', str(Path(__file__).parent / '.auth' / f'{identity}.dpapi'))
                data.setdefault('LOGS_PATH', str(Path(__file__).parent / 'logs'))
            if 'ACCESS_LEVEL' not in data:
                levels = {
                    'AX troubleshooting (read-only to AX)': 'read_only',
                    'MR troubleshooting (read-only to MR)': 'read_only',
                    'Performance tuning for AX (write to AX)': 'read_write',
                    'Troubleshooting and tuning entity store (write to AXDW)': 'read_write',
                }
                if data.get('ACCESS_REASON') not in levels:
                    raise ValueError('Unknown reason; an advanced profile must declare ACCESS_LEVEL')
                data['ACCESS_LEVEL'] = levels[data['ACCESS_REASON']]
            def text(key: str, default: str = '') -> str:
                value = data.get(key, default)
                if not isinstance(value, str):
                    raise ValueError(f'{key} must be a quoted string')
                return value.strip()
            def boolean(key: str, default: bool) -> bool:
                value = data.get(key, default)
                if isinstance(value, bool):
                    return value
                if isinstance(value, str) and value.lower() in {'true', 'false'}:
                    return value.lower() == 'true'
                raise ValueError(f'{key} must be true or false')
            def positive(key: str, default: int, maximum: int) -> int:
                value = data.get(key, default)
                if isinstance(value, bool):
                    raise ValueError(f'{key} must be an integer')
                number = int(value)
                if str(number) != str(value) or not 1 <= number <= maximum:
                    raise ValueError(f'{key} must be between 1 and {maximum}')
                return number
            base = path.resolve().parent
            def local_path(key: str, default: str) -> Path:
                return (base / text(key, default)).resolve()
            project = text('LCS_PROJECT_ID')
            if not project.isdigit():
                raise ValueError('LCS_PROJECT_ID must be numeric')
            environment = text('ENVIRONMENT_ID')
            if not environment and not text('ENVIRONMENT_URL'):
                raise ValueError('ENVIRONMENT_URL or ENVIRONMENT_ID is required')
            level = text('ACCESS_LEVEL', 'read_only')
            if level not in {'read_only', 'read_write'}:
                raise ValueError('ACCESS_LEVEL must be read_only or read_write')
            reason, details = text('ACCESS_REASON'), text('ACCESS_DETAILS')
            if not bootstrap and (not reason or reason.startswith('REPLACE_') or not details):
                raise ValueError('Set ACCESS_REASON to the exact tenant option label and provide ACCESS_DETAILS')
            selectors = data.get('selectors', {})
            if not isinstance(selectors, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in selectors.items()):
                raise ValueError('selectors must map strings to CSS selector strings')
            known_keys = ENV_KEYS | {'selectors'}
            if any(key not in known_keys for key in data):
                raise ValueError('Unknown configuration key; check spelling')
            if reason in {'AX troubleshooting (read-only to AX)', 'MR troubleshooting (read-only to MR)'} and level != 'read_only':
                raise ValueError('The selected LCS reason requires ACCESS_LEVEL read_only')
            if reason in {'Performance tuning for AX (write to AX)', 'Troubleshooting and tuning entity store (write to AXDW)'} and level != 'read_write':
                raise ValueError('The selected LCS reason requires ACCESS_LEVEL read_write')
            selector_keys = {
                'environment_link', 'maintain', 'enable_access', 'enable_dialog', 'ip_address',
                'enable_submit', 'accounts', 'reason', 'reason_list', 'details', 'request_access',
                'rows', 'server_database', 'username', 'password', 'password_reveal', 'expires_at',
                'expiry_format', 'row_reason', 'row_details', 'disable_access', 'disable_dialog',
                'disable_ip_address', 'disable_submit', 'rule_name', 'rule_grid', 'rule_add',
                'rule_delete', 'rule_close', 'rule_add_dialog', 'rule_confirm',
            }
            if any(key not in selector_keys for key in selectors):
                raise ValueError('Unknown selector key; check spelling')
            selectors = {key: value.strip() for key, value in selectors.items()}
            if 'FIREWALL_RULE_NAME' in data:
                rule_name = text('FIREWALL_RULE_NAME')
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', rule_name):
                    raise ValueError('FIREWALL_RULE_NAME requires 1-64 letters, digits, underscores or hyphens')
                selectors['rule_name'] = rule_name
            if selectors.get('expiry_format', '') not in {'', 'iso8601', 'lcs_utc'}:
                raise ValueError('expiry_format must be iso8601 or lcs_utc')
            disable = boolean('DISABLE_ACCESS_AFTER', True)
            required = ['accounts', 'rows', 'server_database', 'username', 'password', 'expires_at']
            if disable and not selectors.get('rule_grid'):
                required.append('disable_ip_address')
            if selectors.get('rule_grid'):
                required += ['enable_dialog', 'rule_add', 'rule_close', 'rule_add_dialog', 'rule_confirm']
                if disable:
                    required.append('rule_delete')
            if not bootstrap and any(not selectors.get(k) for k in required):
                raise ValueError('Calibrate required selectors: ' + ', '.join(required))
            ip = text('PUBLIC_IP')
            if ip:
                address = ipaddress.ip_address(ip)
                if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
                    raise ValueError('PUBLIC_IP must be a global IPv4 address')
            suffix = text('SQL_DNS_SUFFIX', 'database.windows.net')
            if not re.fullmatch(r'[A-Za-z0-9]+(?:\.[A-Za-z0-9-]+)+', suffix):
                raise ValueError('SQL_DNS_SUFFIX must be a DNS suffix')
            environment_url = text('ENVIRONMENT_URL')
            if environment_url:
                target = urlsplit(environment_url)
                if target.scheme != 'https' or target.netloc not in LCS_HOSTS or target.path != f'/V2/EnvironmentDetailsV3New/{project}' or not parse_qs(target.query).get('EnvironmentId'):
                    raise ValueError('ENVIRONMENT_URL must target the configured LCS project')
            timezone = text('BROWSER_TIMEZONE', 'UTC')
            if timezone != 'UTC':
                raise ValueError('Only verified UTC browser timezone is currently supported')
            try:
                import pyodbc
                installed = list(pyodbc.drivers())
            except Exception:
                installed = [] # A broken pyodbc is reported by check_runtime, not as a config error.
            auto_driver = next((name for name in ('ODBC Driver 18 for SQL Server', 'ODBC Driver 17 for SQL Server') if name in installed), 'ODBC Driver 18 for SQL Server')
            driver = text('SQL_ODBC_DRIVER', auto_driver)
            if driver not in {'ODBC Driver 17 for SQL Server', 'ODBC Driver 18 for SQL Server'}:
                raise ValueError('Only Microsoft ODBC Drivers 17/18 are supported')
            state_path = local_path('STORAGE_STATE_PATH', './.auth/lcs_auth.enc')
            key_path = local_path('AUTH_KEY_PATH', '') if text('AUTH_KEY_PATH') else None
            if key_path == state_path:
                raise ValueError('AUTH_KEY_PATH and STORAGE_STATE_PATH must be different files')
            return cls(project, environment, level, reason, details,
                       local_path('SQL_SCRIPTS_PATH', './sql_scripts'),
                       state_path,
                       local_path('LOGS_PATH', './logs'),
                       boolean('CONTINUE_ON_ERROR', False), disable, ip, suffix,
                       positive('SQL_TIMEOUT_SECONDS', 60, 3600),
                       positive('MAX_RESULT_ROWS', 100, 10000), dict(selectors),
                       environment_url, timezone, driver,
                       key_path, minimal)
        except (OSError, ValueError, TypeError, yaml.YAMLError):
            # YAML/parser errors may quote secret-bearing config lines.
            raise AutomationError('configuration', 'Invalid configuration. Paste a complete HTTPS LCS environment URL, an exact supported ACCESS_REASON, non-empty ACCESS_DETAILS, and a valid FIREWALL_RULE_NAME. Remove duplicate YAML keys/stale advanced environment overrides. See README.md#configuration for the fields and README.md#advanced-profiles for profiles.') from None
