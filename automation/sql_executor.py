"""Local Azure SQL runner; scripts must be trusted, transaction-compatible T-SQL."""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
import re
import time
from pathlib import Path
from typing import Any

try:
    import pyodbc
except ImportError:  # Reported clearly by check_runtime / execute_sql_scripts when SQL is needed.
    pyodbc = None  # type: ignore[assignment]

from automation_support import AutomationError, Config, Credentials, odbc_codes, safe_file_name, timestamp, utcnow


def split_batches(sql: str) -> list[str]:
    """Recognize bare GO lines outside strings/comments, without sqlcmd substitution.

    Reject GO repeat counts and sqlcmd commands instead of accidentally replaying
    data changes. Quoted identifiers and nested block comments are tracked.
    """
    batches: list[str] = []
    lines: list[str] = []
    state = 'normal'
    depth = 0
    for line in sql.splitlines(keepends=True):
        if state == 'normal':
            if re.fullmatch(r'\s*GO\s*(?:--[^\r\n]*)?\s*', line, re.IGNORECASE):
                if ''.join(lines).strip():
                    batches.append(''.join(lines))
                lines = []
                continue
            if re.match(r'\s*GO\s+\d', line, re.IGNORECASE) or re.match(r'\s*(?:[:!]|!!)', line):
                raise AutomationError('script_execution', 'GO repetition and sqlcmd directives are unsupported; convert the script to plain T-SQL.')
        lines.append(line)
        i = 0
        while i < len(line):
            pair = line[i:i + 2]
            char = line[i]
            if state == 'normal':
                if pair == '--':
                    break
                if pair == '/*':
                    state, depth = 'comment', 1
                    i += 2
                    continue
                if char in {"'", '"', '['}:
                    state = {"'": 'string', '"': 'quoted', '[': 'bracket'}[char]
            elif state == 'comment':
                if pair == '/*':
                    depth += 1
                    i += 2
                    continue
                if pair == '*/':
                    depth -= 1
                    if depth == 0:
                        state = 'normal'
                    i += 2
                    continue
            else:
                end = {'string': "'", 'quoted': '"', 'bracket': ']'}[state]
                if char == end:
                    if i + 1 < len(line) and line[i + 1] == end:
                        i += 2
                        continue
                    state = 'normal'
            i += 1
    if state != 'normal':
        raise AutomationError('script_execution', 'SQL contains an unterminated string, identifier, or block comment.')
    if ''.join(lines).strip():
        batches.append(''.join(lines))
    return batches


def odbc_escape(value: str) -> str:
    return '{' + value.replace('}', '}}') + '}'


def connection_string(credentials: Credentials, driver: str = 'ODBC Driver 18 for SQL Server') -> str:
    return (
        f'DRIVER={odbc_escape(driver)};'
        f'SERVER={odbc_escape(credentials.server)};'
        f'DATABASE={odbc_escape(credentials.database)};'
        f'UID={odbc_escape(credentials.username)};'
        f'PWD={odbc_escape(credentials.password)};'
        'Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
    )


def discover_scripts(path: Path) -> list[Path]:
    folder = safe_file_name(path)
    try:
        if not path.is_dir():
            raise AutomationError('configuration', f'The SQL scripts folder {folder} does not exist. Create it and put the reviewed .sql files directly inside it.')
        files = sorted((p for p in path.iterdir() if p.is_file() and p.suffix.lower() == '.sql'), key=lambda p: p.name)
    except OSError as error:
        code = getattr(error, 'winerror', None) or error.errno or 'unknown'
        raise AutomationError('configuration', f'The SQL scripts folder {folder} cannot be read (error {code}). Check its permissions.') from None
    if not files:
        raise AutomationError('configuration', f'The SQL scripts folder {folder} contains no .sql files. Only top-level .sql files are run; subfolders are ignored.')
    return files


def read_script(file: Path) -> str:
    """UTF-8 (with or without BOM) SQL text; other encodings are named, not guessed."""
    name = safe_file_name(file)
    try:
        content = file.read_bytes()
    except OSError as error:
        code = getattr(error, 'winerror', None) or error.errno or 'unknown'
        raise AutomationError('configuration', f'Cannot read SQL script {name} (error {code}). Check its permissions and that it is not locked or still syncing.') from None
    if content.startswith((b'\xff\xfe', b'\xfe\xff')):
        raise AutomationError('configuration', f'SQL script {name} is saved as UTF-16 ("Unicode" in SSMS/Notepad). Save it as UTF-8 and rerun.')
    try:
        return content.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise AutomationError('configuration', f'SQL script {name} is not UTF-8 text (probably ANSI). Save it as UTF-8 and rerun.') from None


def script_batches(file: Path) -> tuple[str, ...]:
    name = safe_file_name(file)
    try:
        batches = tuple(split_batches(read_script(file)))
    except AutomationError as error:
        if error.message.startswith(('Cannot read SQL script', 'SQL script')):
            raise
        raise AutomationError('configuration', f'SQL script {name}: {error.message}') from None
    if not batches:
        raise AutomationError('configuration', f'SQL script {name} is empty. Supply non-empty plain T-SQL or remove the file.')
    return batches


@dataclass(frozen=True)
class PreparedScript:
    name: str
    batches: tuple[str, ...]


def prepare_scripts(path: Path) -> list[PreparedScript]:
    """Snapshot reviewed batches before any grant; do not reread files afterward."""
    return [PreparedScript(file.name, script_batches(file)) for file in discover_scripts(path)]


def validate_scripts(path: Path) -> list[Path]:
    """Reject unreadable/unsupported/empty scripts before granting any access."""
    files = discover_scripts(path)
    for file in files:
        script_batches(file)
    return files


def scrub(value: Any, secrets: tuple[str, ...]) -> Any:
    """Final defense, including SQL result cells, filenames and dict keys."""
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, '[REDACTED]')
        return value
    if isinstance(value, dict):
        return {scrub(str(k), secrets): scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v, secrets) for v in value]
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return '[BINARY OMITTED]'
    return scrub(str(value), secrets)


def safe_sql_error(error: pyodbc.Error) -> str:
    # Raw SQL Server messages can echo SQL literals, parameters and passwords.
    state = str(error.args[0]) if error.args else ''
    if not re.fullmatch(r'[A-Z0-9]{5}', state):
        state = 'unknown'
    return f'SQL operation failed (SQLSTATE {state}). Check permissions, T-SQL syntax, query timeout, and JIT/firewall validity; driver details suppressed for security.'


# Azure SQL guidance: retry after 5 s, doubling up to 60 s. A new firewall rule
# can take up to about 5 minutes to apply, and a new JIT login can lag.
RETRY_FIRST_SECONDS = 5
RETRY_MAX_SECONDS = 60
RETRY_BUDGET_SECONDS = 300
NETWORK_ATTEMPTS = 3
FIREWALL_REFUSED = 40615
LOGIN_FAILED = 18456
CLIENT_IP = re.compile(r"IP address '(\d{1,3}(?:\.\d{1,3}){3})'")


def refused_client_ip(error: BaseException) -> str | None:
    """The client IPv4 Azure SQL reports in error 40615; nothing else of the message is kept."""
    for argument in error.args[1:]:
        match = CLIENT_IP.search(str(argument))
        if match:
            try:
                return str(ipaddress.IPv4Address(match.group(1)))
            except ValueError:
                return None
    return None


def connection_failure(codes: dict[str, Any], attempts: int, waited: float) -> str:
    native = ', '.join(str(number) for number in codes.get('native', [])) or 'none'
    return (f'Could not connect to Azure SQL after {attempts} attempt(s) over {waited:g} s (SQLSTATE {codes.get("sqlstate", "unknown")}, native {native}). '
            'Check outbound TCP 1433 and, for the Redirect connection policy, TCP 11000-11999 to Azure SQL, plus VPN/proxy routing and DNS '
            'for the server. See README.md#troubleshooting.')


def connect_with_retry(credentials: Credentials, config: Config, firewall_ip: str | None, ip_source: str | None) -> tuple[Any, int, float]:
    """Open the connection and run SELECT 1. Only connecting is retried, never scripts."""
    attempts = 0
    waited = 0.0
    delay = float(RETRY_FIRST_SECONDS)
    network_failures = 0
    while True:
        attempts += 1
        credentials.ensure_valid('sql_connection')
        connection: Any = None
        try:
            connection = pyodbc.connect(connection_string(credentials, config.odbc_driver), autocommit=False, timeout=30)
            connection.timeout = config.sql_timeout
            cursor = connection.cursor()
            try:
                cursor.execute('SELECT 1')
                row = cursor.fetchone()
                if row is None or row[0] != 1:
                    raise AutomationError('sql_connection', 'SQL connectivity preflight returned an unexpected result.')
            finally:
                cursor.close()
            connection.rollback()
            return connection, attempts, waited
        except pyodbc.Error as error:
            if connection is not None:
                connection.close()
            codes = odbc_codes(error) or {'sqlstate': 'unknown'}
            natives = codes.get('native', [])
            if codes.get('sqlstate') == 'IM002':
                raise AutomationError('sql_connection', f'The ODBC driver "{config.odbc_driver}" was not found by the ODBC driver manager. '
                                      'Rerun run.cmd to reinstall Microsoft ODBC Driver 18 for SQL Server (x64).') from None
            if FIREWALL_REFUSED in natives:
                seen = refused_client_ip(error)
                if seen and firewall_ip and seen != firewall_ip:
                    detected = {'config': 'from PUBLIC_IP in config.yaml', 'auto_direct': 'detected directly',
                                'auto_proxy': 'detected through the web proxy'}.get(ip_source or '', 'detected')
                    raise AutomationError('sql_connection', f'Azure SQL saw this computer as {seen}, but the LCS firewall rule was created for {firewall_ip} '
                                          f'({detected}). Your SQL traffic leaves from a different address than your web traffic (proxy, VPN or split tunnel). '
                                          f'Add PUBLIC_IP: "{seen}" to config.yaml and rerun; the rule for {firewall_ip} is removed by cleanup.') from None
                reason = f'Azure SQL still refuses {seen or firewall_ip or "this computer"} (error 40615). The new LCS firewall rule may not have applied yet.'
            elif LOGIN_FAILED in natives:
                reason = 'Azure SQL still rejects the JIT login (error 18456). The new credential may not be active yet, or it was revoked.'
            else:
                network_failures += 1
                if network_failures >= NETWORK_ATTEMPTS:
                    raise AutomationError('sql_connection', connection_failure(codes, attempts, waited)) from None
                reason = ''
            remaining = (credentials.expires_at - utcnow()).total_seconds()
            if waited + delay > RETRY_BUDGET_SECONDS or delay >= remaining:
                raise AutomationError('sql_connection', (reason + ' ' if reason else '') + f'Gave up after {attempts} attempt(s) over {waited:g} s. '
                                      'Retry later; if 40615 persists, confirm with IT which public IPv4 your SQL traffic uses and set PUBLIC_IP in config.yaml.') from None
            time.sleep(delay)
            waited += delay
            delay = min(delay * 2, RETRY_MAX_SECONDS)
        except Exception:
            if connection is not None:
                connection.close()
            raise


def execute_sql_scripts(credentials: Credentials, config: Config, files: list[Path] | list[PreparedScript] | None = None, *,
                        firewall_ip: str | None = None, ip_source: str | None = None) -> dict[str, Any]:
    if pyodbc is None:
        raise AutomationError('sql_connection', 'The pyodbc ODBC module could not load. Rerun run.cmd to repair automation/.venv.')
    files = prepare_scripts(config.scripts_path) if files is None else files
    results: dict[str, Any] = {
        'total_scripts': len(files), 'scripts_executed': 0, 'scripts_failed': 0,
        'execution_time_seconds': 0.0, 'details': [],
    }
    started = time.monotonic()
    connection, attempts, waited = connect_with_retry(credentials, config, firewall_ip, ip_source)
    results['sql_connection'] = {'attempts': attempts, 'waited_seconds': waited}
    try:
        for file in files:
            script_start = time.monotonic()
            detail: dict[str, Any] = {'script': file.name, 'started_at': timestamp(utcnow()), 'rows_affected': 0, 'result_sets': []}
            cursor = None
            try:
                credentials.ensure_valid()
                # Read/validate complete script before executing any batch.
                batches = file.batches if isinstance(file, PreparedScript) else split_batches(file.read_text(encoding='utf-8-sig'))
                if not batches:
                    raise AutomationError('script_execution', 'SQL script is empty.')
                cursor = connection.cursor()
                for batch in batches:
                    credentials.ensure_valid()
                    cursor.execute(batch)
                    while True:
                        credentials.ensure_valid()
                        if cursor.rowcount >= 0:
                            detail['rows_affected'] += cursor.rowcount
                        if cursor.description:
                            columns = [str(column[0]) for column in cursor.description]
                            rows: list[Any] = []
                            fetched = 0
                            while True:
                                credentials.ensure_valid()
                                chunk = cursor.fetchmany(256)
                                if not chunk:
                                    break
                                fetched += len(chunk)
                                remaining = config.max_result_rows - len(rows)
                                if remaining > 0:
                                    rows.extend([list(row) for row in chunk[:remaining]])
                            detail['result_sets'].append({'columns': columns, 'rows': rows, 'rows_returned': fetched, 'truncated': fetched > len(rows)})
                        if not cursor.nextset():
                            break
                credentials.ensure_valid()
                connection.commit()
                detail['status'] = 'success'
                results['scripts_executed'] += 1
            except (pyodbc.Error, OSError, UnicodeError, AutomationError) as error:
                # Abort if rollback itself fails: connection is not safe to reuse.
                try:
                    connection.rollback()
                except pyodbc.Error:
                    raise AutomationError('script_execution', 'Rollback failed; database state is uncertain. No scripts were replayed; inspect the database manually.') from None
                detail['status'] = 'failed'
                detail['rows_affected'] = 0
                detail['result_sets'] = []
                detail['error'] = safe_sql_error(error) if isinstance(error, pyodbc.Error) else (
                    error.message if isinstance(error, AutomationError) else 'Cannot read SQL script; check file permissions and UTF-8 encoding.')
                results['scripts_failed'] += 1
            finally:
                if cursor is not None:
                    cursor.close()
                detail['ended_at'] = timestamp(utcnow())
                detail['duration_ms'] = round((time.monotonic() - script_start) * 1000)
                results['details'].append(scrub(detail, (credentials.password,)))
            if detail['status'] == 'failed' and (not config.continue_on_error or utcnow() >= credentials.expires_at):
                break
    finally:
        connection.close()
        results['execution_time_seconds'] = round(time.monotonic() - started, 3)
    return results
