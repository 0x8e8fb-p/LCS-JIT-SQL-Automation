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
from pathlib import Path
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
            if 'selectors' not in data:
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
            import pyodbc
            installed = pyodbc.drivers()
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
                       key_path)
        except (OSError, ValueError, TypeError, yaml.YAMLError):
            # YAML/parser errors may quote secret-bearing config lines.
            raise AutomationError('configuration', 'Invalid configuration. Paste a complete HTTPS LCS environment URL, an exact supported ACCESS_REASON, non-empty ACCESS_DETAILS, and a valid FIREWALL_RULE_NAME. Remove duplicate YAML keys/stale advanced environment overrides. See automation/README.md for advanced profiles.') from None
