"""Local Azure SQL runner; scripts must be trusted, transaction-compatible T-SQL."""
from __future__ import annotations

import math
import re
import time
from pathlib import Path
from typing import Any

import pyodbc

from automation_support import AutomationError, Config, Credentials, timestamp, utcnow


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
    try:
        if not path.is_dir():
            raise OSError('directory missing')
        files = sorted((p for p in path.iterdir() if p.is_file() and p.suffix.lower() == '.sql'), key=lambda p: p.name)
        if not files:
            raise OSError('no files')
        return files
    except OSError:
        raise AutomationError('configuration', 'SQL_SCRIPTS_PATH must be a readable folder containing .sql files.') from None


def validate_scripts(path: Path) -> list[Path]:
    """Reject unreadable/unsupported/empty scripts before granting any access."""
    files = discover_scripts(path)
    for file in files:
        try:
            if not split_batches(file.read_text(encoding='utf-8-sig')):
                raise AutomationError('configuration', 'A SQL script is empty. Supply non-empty UTF-8 plain T-SQL files.')
        except (OSError, UnicodeError):
            raise AutomationError('configuration', 'Cannot read all SQL scripts. Check permissions and UTF-8 encoding before requesting access.') from None
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


def execute_sql_scripts(credentials: Credentials, config: Config, files: list[Path] | None = None) -> dict[str, Any]:
    files = discover_scripts(config.scripts_path) if files is None else files
    results: dict[str, Any] = {
        'total_scripts': len(files), 'scripts_executed': 0, 'scripts_failed': 0,
        'execution_time_seconds': 0.0, 'details': [],
    }
    started = time.monotonic()
    credentials.ensure_valid('sql_connection')
    connection: Any = None
    # Retrying a connection/preflight is safe; script execution is NEVER retried.
    for attempt in range(2):
        credentials.ensure_valid('sql_connection')
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
            break
        except pyodbc.Error:
            if connection is not None:
                connection.close()
                connection = None
            if attempt == 0:
                time.sleep(2)
            else:
                raise AutomationError('sql_connection', 'Azure SQL connection/preflight failed twice. Verify the configured ODBC driver, outbound TCP 1433/Azure SQL redirect ports, source egress IP, active firewall/JIT window, DNS, TLS, and database movement status.') from None
        except Exception:
            if connection is not None:
                connection.close()
            raise
    try:
        for file in files:
            script_start = time.monotonic()
            detail: dict[str, Any] = {'script': file.name, 'started_at': timestamp(utcnow()), 'rows_affected': 0, 'result_sets': []}
            cursor = None
            try:
                credentials.ensure_valid()
                # Read/validate complete script before executing any batch.
                batches = split_batches(file.read_text(encoding='utf-8-sig'))
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
