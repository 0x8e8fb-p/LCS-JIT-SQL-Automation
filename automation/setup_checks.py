"""Setup probes run by setup.ps1 with 'python -I'. Standard library first; no project imports.

    python -I setup_checks.py packages <requirements.txt>   exact pins installed and importable
    python -I setup_checks.py odbc                          Microsoft ODBC Driver 18 or 17 installed
    python -I setup_checks.py chromium                      the full Chromium (channel 'chromium') starts
Exit code 0 means OK; otherwise one line explains the first problem.
"""
from __future__ import annotations

import sys
from pathlib import Path

DRIVERS = ('ODBC Driver 18 for SQL Server', 'ODBC Driver 17 for SQL Server')


def check_packages(requirements: Path) -> str | None:
    """Only 'name==version' lines (and comments) are supported, so the check stays exact."""
    from importlib.metadata import PackageNotFoundError, version
    for raw in requirements.read_text(encoding='utf-8-sig').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        name, separator, wanted = line.partition('==')
        name, wanted = name.strip(), wanted.strip()
        if not separator or not name or not wanted or any(mark in name + wanted for mark in ';[]<>=~! '):
            return f'unsupported requirements line (use name==version only): {line}'
        try:
            installed = version(name)
        except PackageNotFoundError:
            return f'missing package: {name}'
        if installed != wanted:
            return f'{name} {installed} is installed, {wanted} is required'
    try:
        import cryptography.fernet  # noqa: F401
        import playwright.sync_api  # noqa: F401
        import pyodbc  # noqa: F401
        import yaml  # noqa: F401
    except ImportError as error:
        return f'cannot import {error.name or "a package"} ({type(error).__name__})'
    return None


def check_odbc() -> str | None:
    try:
        import pyodbc
        installed = pyodbc.drivers()
    except Exception as error:
        return f'pyodbc cannot load ({type(error).__name__})'
    return None if any(driver in installed for driver in DRIVERS) else 'Microsoft ODBC Driver 18 or 17 for SQL Server is not installed'


def check_chromium() -> str | None:
    """The same binary as the runs use: full Chromium, new headless mode."""
    from playwright.sync_api import Error, sync_playwright
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel='chromium', headless=True, timeout=120000)
            browser.close()
    except Error as error:
        text = str(error)
        if "Executable doesn't exist" in text or 'playwright install' in text:
            return 'Chromium is not installed'
        return f'Chromium did not start ({type(error).__name__})'
    return None


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else ''
    if command == 'packages' and len(argv) == 3:
        problem = check_packages(Path(argv[2]))
    elif command == 'odbc':
        problem = check_odbc()
    elif command == 'chromium':
        problem = check_chromium()
    else:
        problem = 'usage: setup_checks.py packages <requirements.txt> | odbc | chromium'
    if problem:
        print(problem)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
