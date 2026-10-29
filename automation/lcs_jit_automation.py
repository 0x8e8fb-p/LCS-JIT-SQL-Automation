"""LCS browser adapter. All selectors require tenant validation; no MFA bypass."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta, timezone
import uuid
import ctypes
from pathlib import Path
from typing import Any, Literal, Sequence, cast
from datetime import datetime
from playwright._impl._api_structures import SetCookieParam, StorageState
import sys
from urllib.request import urlopen

from cryptography.fernet import Fernet, InvalidToken
from playwright.sync_api import Browser, BrowserContext, Locator, Page, Playwright, Error as BrowserError

from automation_support import (AutomationError, Config, Credentials, LCS_HOSTS, browser_category, date_shape, default_rule_name, describe_error, parse_expiry,
                                parse_lcs_datetime, parse_server_database, timestamp, utcnow)

BROWSER_CHANNEL = 'chromium'  # Full Chromium for headless and visible runs (no headless shell).
BROWSER_LOCALE = 'en-US'
BROWSER_LAUNCH_TIMEOUT_MS = 120000  # First start can be slow while security software scans.

LCS_URL = 'https://lcs.dynamics.com'
MASK_CHARACTERS = {'*', '•', '●'}


def is_masked(value: str) -> bool:
    return bool(value) and set(value) <= MASK_CHARACTERS


def collapse(value: str) -> str:
    """Whitespace-insensitive comparison of LCS cell text."""
    return ' '.join(value.split())


def protected_local_key(path: Path, *, create: bool = False) -> bytes:
    """Windows DPAPI binds a Fernet key to the current Windows identity."""
    if os.name != 'nt':
        raise AutomationError('authentication', 'AUTH_KEY_PATH requires Windows DPAPI; otherwise inject LCS_AUTH_KEY.')
    class Blob(ctypes.Structure):
        _fields_ = [('size', ctypes.c_ulong), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    def transform(data: bytes, protect: bool) -> bytes:
        buffer = ctypes.create_string_buffer(data)
        source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        target = Blob()
        function = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
        if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
            raise AutomationError('authentication', 'Windows DPAPI could not protect/unprotect the local auth key.')
        try:
            return ctypes.string_at(target.data, target.size)
        finally:
            ctypes.windll.kernel32.LocalFree(target.data)
    try:
        if not path.exists() and create:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as handle:
                handle.write(transform(Fernet.generate_key(), True))
        return transform(path.read_bytes(), False)
    except OSError:
        raise AutomationError('authentication', 'DPAPI key unavailable; bootstrap with the same Windows task identity.') from None


def cipher(key_path: Path | None = None, *, create: bool = False) -> Fernet:
    try:
        key = os.environ.get('LCS_AUTH_KEY')
        if key:
            return Fernet(key.encode('ascii'))
        if key_path is not None:
            return Fernet(protected_local_key(key_path, create=create))
        raise KeyError('LCS_AUTH_KEY')
    except (KeyError, ValueError, UnicodeError):
        raise AutomationError('authentication', 'Set LCS_AUTH_KEY to a Fernet key from your local secret manager (see README).') from None


def save_auth(context: BrowserContext, path: Path, key_path: Path | None = None) -> None:
    encrypted = cipher(key_path, create=True).encrypt(json.dumps(context.storage_state(indexed_db=True)).encode('utf-8'))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        # Ciphertext only; exclusive open prevents following an existing temporary symlink.
        with temporary.open('xb') as handle:
            os.chmod(temporary, 0o600)
            handle.write(encrypted)
        temporary.replace(path)
    except OSError:
        raise AutomationError('authentication', 'Cannot save encrypted auth state. Check path permissions and disk space.') from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            raise AutomationError('authentication', 'Cannot remove temporary encrypted auth file. Check directory permissions.') from None


def load_auth(path: Path, key_path: Path | None = None) -> StorageState:
    try:
        state = json.loads(cipher(key_path).decrypt(path.read_bytes()))
        if not isinstance(state, dict) or 'cookies' not in state or 'origins' not in state:
            raise ValueError('invalid state')
        return cast(StorageState, state)
    except (OSError, InvalidToken, ValueError):
        raise AutomationError('authentication', 'Encrypted authentication state is missing or invalid. Run ./run.ps1 -ForceInteractive with the same Windows identity/auth key.') from None


def get_public_ip(config: Config) -> str:
    if config.public_ip:
        return config.public_ip
    try:
        with urlopen('https://api.ipify.org', timeout=10) as response:
            value = response.read(128).decode('ascii').strip()
        address = ipaddress.ip_address(value)
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
            raise ValueError('global IPv4 required')
        return str(address)
    except Exception:
        raise AutomationError('ip_rule', 'Public IPv4 detection failed. Set PUBLIC_IP to the SQL host egress IPv4 and verify proxy/VPN routing.') from None


class LCSAutomation:
    # Limits as class attributes so slow machines and tests can adjust them.
    ACTION_TIMEOUT_MS = 20000        # clicks, fills and element reads
    NAVIGATION_TIMEOUT_MS = 60000    # page loads and the Database accounts section
    IDLE_TIMEOUT_MS = 120000         # LCS asynchronous processing overlay
    GRID_SETTLE_POLL_MS = 500
    GRID_SETTLE_POLLS = 3            # unchanged row count means the grid is bound
    GRID_EMPTY_SETTLE_MS = 6000      # an empty grid must stay empty this long
    GRID_SETTLE_TIMEOUT_MS = 20000
    CONFIRM_TIMEOUT_MS = 10000       # delete confirmation dialog
    RULE_CONFIRM_TIMEOUT_MS = 180000  # add-rule dialog closing after Create
    RULE_REFRESHES = 3               # fresh grids checked for a newly created rule
    RULE_REFRESH_PAUSE_SECONDS = 5
    REVEAL_TIMEOUT_MS = 5000         # password reveal
    CREDENTIAL_FIRST_WAIT_SECONDS = 5
    CREDENTIAL_POLL_INTERVAL_SECONDS = 10
    CREDENTIAL_POLL_SECONDS = 180    # the request is submitted once, then only polled
    SIGN_IN_GRACE_MS = 10000         # silent single sign-on hops through login pages and back

    def __init__(self, config: Config, playwright: Playwright, log_dir: Path, *, bootstrap: bool = False, headed: bool = False):
        self.config = config
        self.log_dir = log_dir
        self.browser: Browser | None = None
        self.lcs_date_format = ''
        self.date_order_hint = ''
        headless = not (bootstrap or headed)
        profile_dir = self._profile_dir()
        try:
            state = None if bootstrap else self._initial_state(profile_dir)
            # One binary for every mode: the full Chromium (channel 'chromium') runs
            # headless and visible runs alike. en-US + UTC make LCS render the
            # English labels and US dates the adapter was calibrated against.
            if profile_dir is not None:
                profile_dir.mkdir(parents=True, exist_ok=True)
                self.context = playwright.chromium.launch_persistent_context(
                    user_data_dir=str(profile_dir),
                    channel=BROWSER_CHANNEL,
                    headless=headless,
                    accept_downloads=False,
                    timezone_id=config.browser_timezone,
                    locale=BROWSER_LOCALE,
                    timeout=BROWSER_LAUNCH_TIMEOUT_MS,
                )
                if state is not None and state.get('cookies'):
                    try:
                        self.context.add_cookies(cast(Sequence[SetCookieParam], state['cookies']))
                    except Exception:
                        pass
                self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
            else:
                self.browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=headless, timeout=BROWSER_LAUNCH_TIMEOUT_MS)
                self.context = self.browser.new_context(storage_state=state, accept_downloads=False,
                                                        timezone_id=config.browser_timezone, locale=BROWSER_LOCALE)
                self.page = self.context.new_page()
            self.context.set_default_timeout(self.ACTION_TIMEOUT_MS)
            self.context.set_default_navigation_timeout(self.NAVIGATION_TIMEOUT_MS)
        except AutomationError:
            self.close()
            raise
        except Exception as error:
            self.close()
            raise AutomationError('browser_start', self._browser_start_message(error, profile_dir)) from None
        self.ip_rule_attempted = False
        self.public_ip = ''
        self.requested_at = utcnow()
        self.firewall_expires_at = utcnow()
        self.step = 'authentication'
        self.rule_name = ''
        self.rule_created = False

    @staticmethod
    def _browser_start_message(error: BaseException, profile_dir: Path | None) -> str:
        """Specific, secret-free reason why Chromium did not start."""
        category = str(describe_error(error).get('browser', ''))
        if category == 'profile_in_use':
            folder = f' ({profile_dir.name})' if profile_dir is not None else ''
            return (f'The saved browser profile{folder} is in use by another Chromium window. Close browser windows opened by this tool '
                    '(or end chrome.exe processes started from automation/browsers) and retry.')
        if category == 'executable_missing':
            return 'Playwright Chromium is missing or incomplete. Rerun run.cmd to reinstall it.'
        if category == 'timeout':
            return 'Chromium did not start within the time limit. Retry; security software scanning a new browser can slow the first start.'
        return ('Chromium could not start. Security software or application control may be blocking automation/browsers; '
                'ask IT to allow it, or rerun run.cmd to reinstall Chromium. A safe diagnostic is in automation/logs/diagnostics.')

    def _profile_dir(self) -> Path | None:
        if self.config.auth_key_path is None:
            return None
        return self.config.state_path.with_name(f'{self.config.state_path.stem}.profile')

    def _initial_state(self, profile_dir: Path | None) -> StorageState | None:
        if self.config.state_path.exists() or profile_dir is None or not profile_dir.exists():
            return load_auth(self.config.state_path, self.config.auth_key_path)
        return None

    def close(self) -> None:
        try:
            if hasattr(self, 'context') and self.context is not None:
                self.context.close()
        finally:
            if getattr(self, 'browser', None) is not None and self.browser is not None:
                self.browser.close()

    def locator(self, key: str, *, scope: Page | Locator | None = None) -> Locator:
        root = self.page if scope is None else scope
        css = self.config.selectors.get(key, '')
        if css:
            return root.locator(css)
        roles: dict[str, tuple[Literal['link', 'button', 'menuitem', 'dialog'], str]] = {
            'environment_link': ('link', self.config.environment_id),
            'maintain': ('button', 'Maintain'),
            'enable_access': ('menuitem', 'Enable access'),
            'enable_dialog': ('dialog', 'Enable access'),
            'enable_submit': ('button', 'OK'),
            'request_access': ('button', 'Request access'),
            'disable_access': ('menuitem', 'Disable access'),
            'disable_dialog': ('dialog', 'Disable access'),
            'disable_submit': ('button', 'OK'),
        }
        labels = {'ip_address': 'IP address', 'reason': 'Reason for access', 'details': 'Details'}
        if key in roles:
            role, name = roles[key]
            return root.get_by_role(role, name=name, exact=True)
        if key in labels:
            return root.get_by_label(labels[key], exact=True)
        raise AutomationError(self.step, 'Required selector is missing; calibrate config.yaml against your tenant DOM.')

    def _active_lcs_page(self) -> Page:
        from urllib.parse import urlsplit
        expected_host = urlsplit(self.config.lcs_origin).netloc
        for candidate in reversed(self.context.pages):
            try:
                parsed = urlsplit(candidate.url)
                if parsed.scheme == 'https' and parsed.netloc == expected_host and parsed.path.startswith('/V2/'):
                    return candidate
            except Exception:
                continue
        for candidate in reversed(self.context.pages):
            try:
                parsed = urlsplit(candidate.url)
                if parsed.scheme == 'https' and parsed.netloc in LCS_HOSTS:
                    return candidate
            except Exception:
                continue
        return self.page

    def _complete_lcs_landing(self, target_url: str) -> None:
        from urllib.parse import parse_qs, urlsplit
        self.page = self._active_lcs_page()
        parsed = urlsplit(self.page.url)
        if parsed.netloc in LCS_HOSTS and parsed.path.lower().startswith('/logon/'):
            sign_in = self.page.locator('a.loginLink')
            if sign_in.count() == 1 and sign_in.is_visible():
                try:
                    with self.page.expect_navigation(wait_until='domcontentloaded', timeout=self.NAVIGATION_TIMEOUT_MS):
                        sign_in.click()
                except BrowserError:
                    pass
        self.page = self._active_lcs_page()
        parsed = urlsplit(self.page.url)
        expected = urlsplit(target_url)
        same_target = (
            parsed.path == expected.path
            and [v.lower() for v in parse_qs(parsed.query).get('EnvironmentId', [])]
            == [v.lower() for v in parse_qs(expected.query).get('EnvironmentId', [])]
        )
        if parsed.scheme == 'https' and parsed.netloc in LCS_HOSTS and not same_target:
            self.page.goto(target_url, wait_until='domcontentloaded', timeout=self.NAVIGATION_TIMEOUT_MS)

    def screenshot(self, name: str) -> str | None:
        """Mask BEFORE encoding/writing. Fail closed if accounts container is unknown.

        Unknown/login pages are entirely masked. Never write raw screenshots, HAR,
        video, traces, DOM dumps, or browser console/network output.
        """
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            path = self.log_dir / f'{name}.png'
            accounts_css = self.config.selectors.get('accounts', '')
            accounts = self.page.locator(accounts_css) if accounts_css else None
            on_lcs = self.page.url.startswith(self.config.lcs_origin + '/')
            if on_lcs and accounts is not None and accounts.count() == 1 and accounts.is_visible():
                masks = [accounts, self.page.locator('input, textarea, iframe')]
            else:
                masks = [self.page.locator('body')]
            # Masked pixels only reach disk. No animations or caret leakage.
            self.page.screenshot(path=str(path), mask=masks, mask_color='#000000', animations='disabled', caret='hide')
            return str(path.resolve())
        except Exception:
            return None

    def verify_environment(self) -> None:
        """Check origin, configured project, and exact environment before mutations."""
        from urllib.parse import parse_qs, urlsplit
        target = urlsplit(self.page.url)
        expected = urlsplit(self.config.environment_url) if self.config.environment_url else None
        expected_host = expected.netloc if expected is not None else urlsplit(self.config.lcs_origin).netloc
        if target.scheme != 'https' or target.netloc != expected_host:
            raise AutomationError('authentication', 'Authentication expired or sign-in/MFA requires interaction. Run ./run.ps1 -ForceInteractive.')
        if expected is not None:
            if target.path != expected.path or [v.lower() for v in parse_qs(target.query).get('EnvironmentId', [])] != [v.lower() for v in parse_qs(expected.query).get('EnvironmentId', [])]:
                raise AutomationError('environment', 'Environment URL does not match the configured project/environment; refusing access changes.')
        elif target.path != f'/V2/EnvironmentDetailsV3New/{self.config.project_id}':
            raise AutomationError('environment', 'Environment page does not belong to the configured LCS project; refusing access changes.')
        headings = self.page.locator('h1')
        if headings.count() != 1:
            raise AutomationError('environment', 'Expected exactly one environment heading; refusing access changes.')
        name = headings.inner_text().strip()
        if not name or (self.config.environment_id and name != self.config.environment_id):
            raise AutomationError('environment', 'Environment heading does not match ENVIRONMENT_ID; refusing access changes.')
        if not self.config.environment_id:
            self.config.environment_id = name # Discovered only after URL/project/GUID verification.

    def _on_lcs(self) -> bool:
        from urllib.parse import urlsplit
        return (urlsplit(self.page.url).hostname or '').lower() in LCS_HOSTS

    def _landing_problem(self) -> AutomationError | None:
        """Where the browser landed, if that is not the configured LCS host."""
        from urllib.parse import urlsplit
        parsed = urlsplit(self.page.url)
        if parsed.scheme not in {'http', 'https'}:
            return None  # about:blank: nothing loaded yet
        host = (parsed.hostname or '').lower()
        expected = (urlsplit(self.config.lcs_origin).hostname or '').lower()
        if host == expected:
            return None
        shown = host if re.fullmatch(r'[a-z0-9.-]{1,100}', host) else 'another site'
        if host in LCS_HOSTS:
            return AutomationError('environment', f'LCS opened {shown}, but ENVIRONMENT_URL uses {expected}. Copy the environment-details URL from {shown} into config.yaml.')
        return AutomationError('authentication', f'The saved sign-in needs a fresh login (the browser was sent to {shown}). '
                               'Run .\\run.cmd and complete sign-in when asked, or .\\run.cmd -ForceInteractive.')

    def _slow_section(self, what: str) -> AutomationError:
        seconds = self.NAVIGATION_TIMEOUT_MS / 1000
        return AutomationError('environment', f'{what} did not appear within {seconds:g} s. LCS may be slow (retry), or your account may lack '
                               'permission to manage database access for this environment; open the page in a normal browser to check.')

    def _wait_for_section(self, section: Locator) -> bool:
        """True once an LCS section is visible; False on timeout.

        Leaving LCS for longer than the sign-in grace period (federated or
        expired sign-in, another LCS host) raises at once instead of waiting
        out the full limit; quick single sign-on hops are tolerated.
        """
        deadline = time.monotonic() + self.NAVIGATION_TIMEOUT_MS / 1000
        off_lcs_since: float | None = None
        while True:
            now = time.monotonic()
            problem = self._landing_problem()
            if problem is None:
                off_lcs_since = None
                try:
                    if section.first.is_visible():
                        return True
                except BrowserError:
                    pass  # The page is navigating.
            else:
                off_lcs_since = now if off_lcs_since is None else off_lcs_since
                if (now - off_lcs_since) * 1000 >= self.SIGN_IN_GRACE_MS:
                    raise problem
            if now >= deadline:
                if problem is not None:
                    raise problem
                return False
            self.page.wait_for_timeout(250)

    @contextmanager
    def ui(self, what: str, timeout_ms: float, hint: str = '') -> Iterator[None]:
        """Turn browser failures into a message naming the element and the limit."""
        try:
            yield
        except BrowserError as error:
            category = browser_category(error) or 'other'
            if category == 'browser_closed':
                message = f'The automation browser closed during {self.step}. Keep its window open until the run ends.'
            elif category == 'timeout':
                message = f"{what} didn't respond within {timeout_ms / 1000:g} s."
            else:
                message = f'{what} failed in the browser ({category}).'
            raise AutomationError(self.step, f'{message} {hint}'.strip()) from None

    def _pause(self, seconds: float) -> None:
        self.page.wait_for_timeout(seconds * 1000)

    def navigate(self, *, allow_interactive_auth: bool = False) -> None:
        self.step = 'authentication'
        origin_url = self.config.lcs_origin
        url = self.config.environment_url or f'{origin_url}/V2/Project/{self.config.project_id}/'
        slow_attempts = 0
        for attempt in range(3):
            try:
                self.page.goto(url, wait_until='domcontentloaded', timeout=self.NAVIGATION_TIMEOUT_MS)
                self._complete_lcs_landing(url)
                if self.config.environment_url:
                    if not self._wait_for_section(self.locator('accounts')):
                        slow_attempts += 1
                        if slow_attempts < 2:
                            continue  # One reload: the first LCS load after sign-in can be slow.
                        raise self._slow_section('The Database accounts section of the environment page')
                    self.verify_environment()
                    save_auth(self.context, self.config.state_path, self.config.auth_key_path)
                    self.screenshot('01_login')
                    return
                self.locator('environment_link').wait_for(state='visible', timeout=self.NAVIGATION_TIMEOUT_MS)
                if not self.page.url.startswith(origin_url + '/'):
                    raise AutomationError('authentication', 'Authentication expired or MFA/Conditional Access requires interaction. Run .\\run.cmd -ForceInteractive on this computer.')
                save_auth(self.context, self.config.state_path, self.config.auth_key_path)
                self.screenshot('01_login')
                self.locator('environment_link').click()
                self.locator('accounts').wait_for(state='visible', timeout=self.NAVIGATION_TIMEOUT_MS)
                self.verify_environment()
                return
            except AutomationError as auth_error:
                if allow_interactive_auth and auth_error.step == 'authentication':
                    self.bootstrap(navigate_first=False)
                    self.screenshot('01_login')
                    return
                raise
            except BrowserError as error:
                problem = self._landing_problem()
                if problem is not None:
                    # Federated or expired sign-in: fail fast instead of retrying a login page.
                    if allow_interactive_auth and problem.step == 'authentication':
                        self.bootstrap(navigate_first=False)
                        self.screenshot('01_login')
                        return
                    raise problem from None
                category = browser_category(error) or 'other'
                if category.startswith('net::ERR_'):
                    if attempt < 2:
                        time.sleep(2 ** attempt)
                        continue
                    host = origin_url.split('//', 1)[-1]
                    raise AutomationError('network', f'LCS could not be reached ({category}). Check Internet, VPN and proxy access to {host} and Microsoft sign-in.') from None
                if self._on_lcs():
                    if self.page.get_by_role('button', name='Maintain', exact=True).count() and not self.config.environment_url:
                        raise AutomationError('environment', f'Environment not found in project {self.config.project_id}; check ENVIRONMENT_ID and environment_link selector.') from None
                    slow_attempts += 1
                    if slow_attempts < 2:
                        continue  # One reload: the first LCS load after sign-in can be slow.
                    raise self._slow_section('The Database accounts section of the environment page') from None
                if attempt < 2:
                    time.sleep(2 ** attempt)
        if self._on_lcs():
            raise self._slow_section('The Database accounts section of the environment page')
        if allow_interactive_auth:
            self.bootstrap(navigate_first=False)
            self.screenshot('01_login')
            return
        raise AutomationError('authentication', 'Sign-in did not complete after three attempts. Run .\\run.cmd -ForceInteractive; Entra MFA/Conditional Access cannot be bypassed.')

    def bootstrap(self, *, navigate_first: bool = True) -> None:
        origin_url = self.config.lcs_origin
        target_url = self.config.environment_url or f'{origin_url}/V2/Project/{self.config.project_id}/'
        if navigate_first:
            self.page.goto(target_url, wait_until='domcontentloaded', timeout=self.NAVIGATION_TIMEOUT_MS)
        if self.config.environment_url:
            print('Complete sign-in and MFA; wait for the environment page to load, then press Enter here.', file=sys.stderr)
            input()
            self._complete_lcs_landing(target_url)
            if not self.page.url.startswith(origin_url + '/'):
                problem = self._landing_problem()
                if problem is not None and problem.step == 'environment':
                    raise problem
                raise AutomationError('authentication', 'Sign-in did not finish: the browser is not on the LCS environment page yet. '
                                      'Complete sign-in, wait until the environment page shows, then press Enter.')
            try:
                if not self._wait_for_section(self.locator('accounts')):
                    raise self._slow_section('The environment page (Database accounts section)')
                self.page.locator('h1').wait_for(state='visible', timeout=self.NAVIGATION_TIMEOUT_MS)
            except BrowserError:
                raise self._slow_section('The environment page heading') from None
            except AutomationError as problem:
                if problem.step != 'authentication':
                    raise
                raise AutomationError('authentication', 'Sign-in did not finish: the browser left LCS. Complete sign-in, wait until the '
                                      'environment page shows, then press Enter.') from None
            self.verify_environment()
            self.wait_idle()
        else:
            print('Complete sign-in and MFA in the browser; open the project, then press Enter here.', file=sys.stderr)
            input()
            self._complete_lcs_landing(target_url)
            if not self.page.url.startswith(f'{origin_url}/V2/Project/{self.config.project_id}'):
                raise AutomationError('authentication', 'Open the configured LCS project before saving authentication.')
            self.locator('environment_link').wait_for(state='visible', timeout=self.NAVIGATION_TIMEOUT_MS)
            self.wait_idle()
        save_auth(self.context, self.config.state_path, self.config.auth_key_path)

    def enable_ip(self, public_ip: str) -> None:
        self.step = 'ip_rule'
        self.verify_environment()
        self.public_ip = public_ip
        self.firewall_expires_at = utcnow() + timedelta(hours=8)
        if self.config.selectors.get('rule_grid'):
            self.enable_rule_grid(public_ip)
            return
        for attempt in range(2):
            try:
                dialog = self.locator('enable_dialog')
                if not dialog.is_visible():
                    self.locator('maintain').click()
                    self.locator('enable_access').click()
                dialog.wait_for(state='visible')
                self.locator('ip_address', scope=dialog).fill(public_ip)
                # Even if submit times out, cleanup must attempt to remove this IP.
                self.ip_rule_attempted = True
                self.locator('enable_submit', scope=dialog).click()
                dialog.wait_for(state='hidden', timeout=self.NAVIGATION_TIMEOUT_MS)
                self.screenshot('02_ip_rule')
                return
            except BrowserError:
                if attempt == 0:
                    time.sleep(2)
        raise AutomationError('ip_rule', 'IP rule could not be confirmed. Check dialog selectors, LCS permissions, and existing IP rules.')

    def wait_idle(self, timeout: int | None = None) -> None:
        """Wait for LCS async request processing to finish before UI actions."""
        limit = self.IDLE_TIMEOUT_MS if timeout is None else timeout
        try:
            # #ShellBlockingDiv is LCS's full-screen pointer-event interceptor;
            # it has no layout only while no async request is in flight. Interval
            # polling keeps working when the window is minimized.
            self.page.wait_for_function(
                "() => { const block = document.querySelector('#ShellBlockingDiv');"
                " const blocked = block && block.getClientRects().length > 0;"
                " const text = Array.from(document.querySelectorAll('.applicationShell-blockingMessageText'))"
                " .some(el => el.getClientRects().length && /processing|please wait/i.test(el.innerText));"
                " return !blocked && !text; }",
                timeout=limit, polling=500)
        except BrowserError:
            raise AutomationError(self.step, f'LCS did not finish processing within {limit / 1000:g} s; no further UI changes attempted.') from None

    def safe_click(self, locator: Locator, timeout: int | None = None) -> None:
        """Respect visibility/enabled/overlay checks; never dispatch forced JS clicks."""
        self.wait_idle()
        locator.click(timeout=self.ACTION_TIMEOUT_MS if timeout is None else timeout)

    def close_dialog(self, dialog: Locator) -> None:
        self.wait_idle()
        if dialog.is_visible():
            with self.ui('The firewall dialog Close button', self.ACTION_TIMEOUT_MS):
                self.safe_click(self.locator('rule_close', scope=dialog))
                dialog.wait_for(state='hidden', timeout=self.ACTION_TIMEOUT_MS)

    def refresh_environment(self) -> None:
        """Reload only after processing completes; discard stale LCS modal layers."""
        self.wait_idle()
        with self.ui('Reloading the LCS environment page', self.NAVIGATION_TIMEOUT_MS):
            self.page.reload(wait_until='domcontentloaded', timeout=self.NAVIGATION_TIMEOUT_MS)
        if not self._wait_for_section(self.locator('accounts')):
            raise self._slow_section('The Database accounts section of the environment page')
        self.wait_idle()
        self.verify_environment()

    def wait_rows_settled(self, dialog: Locator) -> int:
        """Rows are bound when their count stops changing (empty grids must stay empty longer)."""
        rows = self.rule_rows(dialog)
        started = time.monotonic()
        last = -1
        same = 0
        empty_since: float | None = None
        while True:
            count = rows.count()
            same = same + 1 if count == last else 0
            last = count
            now = time.monotonic()
            if count > 0:
                empty_since = None
                if same >= self.GRID_SETTLE_POLLS - 1:
                    return count
            else:
                empty_since = now if empty_since is None else empty_since
                if (now - empty_since) * 1000 >= self.GRID_EMPTY_SETTLE_MS:
                    return 0
            if (now - started) * 1000 >= self.GRID_SETTLE_TIMEOUT_MS:
                raise AutomationError(self.step, f'The firewall rules grid kept changing for {self.GRID_SETTLE_TIMEOUT_MS / 1000:g} s; '
                                      'nothing was changed. Retry when LCS is less busy.')
            self.page.wait_for_timeout(self.GRID_SETTLE_POLL_MS)

    def open_rule_grid(self) -> Locator:
        self.wait_idle()
        dialog = self.locator('enable_dialog')
        with self.ui('The firewall rules dialog (Maintain > Enable access)', self.NAVIGATION_TIMEOUT_MS,
                     'Check that your account can manage firewall rules for this environment.'):
            if not dialog.is_visible():
                self.safe_click(self.locator('maintain'))
                self.safe_click(self.locator('enable_access'))
            dialog.wait_for(state='visible', timeout=self.NAVIGATION_TIMEOUT_MS)
            self.locator('rule_grid', scope=dialog).wait_for(state='visible', timeout=self.ACTION_TIMEOUT_MS)
            self.page.wait_for_function("() => !Array.from(document.querySelectorAll('[role=dialog] [role=grid]')).some(el => el.getAttribute('aria-busy') === 'true')",
                                        timeout=self.ACTION_TIMEOUT_MS, polling=500)
        # The Dynamics grid shell appears before its asynchronous rows are bound.
        self.wait_rows_settled(dialog)
        return dialog

    def expiry_value(self, text: str, step: str | None = None, now: datetime | None = None) -> datetime:
        """UTC expiry from an LCS cell; fails closed instead of guessing validity."""
        step = step or str(getattr(self, 'step', 'jit_request'))
        if self.config.selectors.get('expiry_format') == 'lcs_utc':
            try:
                parsed = parse_lcs_datetime(text, now or utcnow(), getattr(self, 'date_order_hint', ''))
            except ValueError:
                raise AutomationError(step, f'LCS showed an ambiguous expiry date ({date_shape(text)}) that cannot be read safely. '
                                      'Set the LCS language to English (United States) in your LCS user settings and rerun; '
                                      'the run refuses to guess credential or firewall validity.') from None
            if parsed is None:
                raise AutomationError(step, f'LCS showed an expiry date in an unrecognized format ({date_shape(text)}). '
                                      'Set the LCS language to English (United States) in your LCS user settings and rerun; '
                                      'the run refuses to guess credential or firewall validity.')
            moment, style, ambiguous = parsed
            if not getattr(self, 'lcs_date_format', ''):
                self.lcs_date_format = style  # Reported as lcs_date_format in report.json.
            if not ambiguous:
                self.date_order_hint = style  # Resolves later ambiguous dates on the same page.
            return moment
        try:
            return parse_expiry(text)
        except AutomationError as error:
            raise AutomationError(step, error.message) from None

    def reveal_password(self, row: Locator) -> None:
        if not self.config.selectors.get('password_reveal'):
            return
        cell = self.locator('password', scope=row)
        if not is_masked(self.cell_value(cell)):
            return
        self.locator('password_reveal', scope=row).click()
        deadline = time.monotonic() + self.REVEAL_TIMEOUT_MS / 1000
        while time.monotonic() < deadline and is_masked(self.cell_value(cell)):
            self.page.wait_for_timeout(200)  # The reveal can load the password asynchronously.

    def rule_rows(self, dialog: Locator) -> Locator:
        return self.locator('rule_grid', scope=dialog).locator('.rowTemplate:not(.place-holder)')

    def matching_owned_rows(self, dialog: Locator, step: str | None = None) -> list[Locator]:
        step = step or str(getattr(self, 'step', 'cleanup'))
        matches = []
        for row in self.rule_rows(dialog).all():
            if row.locator("input[name='NetworkSecurityRuleName']").input_value() == self.rule_name:
                if row.locator("input[name='NetworkSecurityRuleIpOrCidr']").input_value() not in {self.public_ip, self.public_ip + '/32'} or row.locator("input[name='NetworkSecurityGroupService']").input_value() != 'AzureSQL':
                    raise AutomationError(step, f'Firewall rule {self.rule_name} does not match this run\'s source IP/service; refusing to change or remove it.')
                matches.append(row)
        if len(matches) > 1:
            raise AutomationError(step, f'More than one firewall rule is named {self.rule_name}; refusing to change or remove any of them.')
        return matches

    def enable_rule_grid(self, public_ip: str) -> None:
        dialog = self.open_rule_grid()
        with self.ui('Reading the firewall rules grid', self.ACTION_TIMEOUT_MS):
            for row in self.rule_rows(dialog).all():
                source = row.locator("input[name='NetworkSecurityRuleIpOrCidr']").input_value()
                service = row.locator("input[name='NetworkSecurityGroupService']").input_value()
                if source in {public_ip, public_ip + '/32'} and service == 'AzureSQL':
                    expiry = self.expiry_value(row.locator("input[name='NetworkSecurityGroupRuleExpiration']").input_value(), 'ip_rule')
                    if expiry <= utcnow():
                        continue # An expired entry provides no access and must not be reused.
                    self.firewall_expires_at = min(self.firewall_expires_at, expiry)
                    self.close_dialog(dialog)
                    self.screenshot('02_existing_ip_rule')
                    return # Existing rule is NOT owned and will never be deleted.
            desired_name = self.config.selectors.get('rule_name', '') or default_rule_name()
            for row in self.rule_rows(dialog).all():
                if row.locator("input[name='NetworkSecurityRuleName']").input_value() == desired_name:
                    raise AutomationError('ip_rule', f'Firewall rule {desired_name} already exists in LCS for a different IP address or service, or it has expired. '
                                          'It is probably left over from an earlier run: remove it in LCS (Maintain > Enable access) and rerun. '
                                          'This tool never changes rules it did not create in the current run.')
        self.rule_name = desired_name
        with self.ui('The Add firewall rule dialog', self.ACTION_TIMEOUT_MS, 'No rule was submitted.'):
            self.safe_click(self.locator('rule_add', scope=dialog))
            add = self.locator('rule_add_dialog')
            add.wait_for(state='visible', timeout=self.ACTION_TIMEOUT_MS)
            self.page.wait_for_function("() => Array.from(document.querySelectorAll('[role=dialog] input[name=Services]')).some(el => el.value === 'AzureSQL')",
                                        timeout=self.ACTION_TIMEOUT_MS, polling=500)
            # Service is left at the LCS default; do not click, fill or change it.
            add.locator("input[name='NameField']").fill(self.rule_name)
            add.locator("input[name='IpOrCidrField']").fill(public_ip)
            add.locator("input[name='IpOrCidrField']").press('Tab')
        self.ip_rule_attempted = True
        # Persist no secrets: retain a recovery record before changing firewall access.
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / 'owned_rule.json').write_text(json.dumps({'name': self.rule_name, 'public_ip': public_ip, 'public_ip_source': self.public_ip_source,
                                                                  'environment_id': self.config.environment_id, 'created_at': timestamp(utcnow())}), encoding='utf-8')
        with self.ui(f'Creating firewall rule {self.rule_name}', self.RULE_CONFIRM_TIMEOUT_MS,
                     f'Check LCS for rule {self.rule_name}; cleanup will still try to remove it.'):
            self.locator('rule_confirm', scope=add).click()
            add.wait_for(state='hidden', timeout=self.RULE_CONFIRM_TIMEOUT_MS)
        self.wait_idle()
        # LCS leaves a non-dialog popupShadow/modalBackground layer after add.
        # Reload after processing instead of forcing a click through that layer.
        for attempt in range(self.RULE_REFRESHES):
            self.refresh_environment()
            dialog = self.open_rule_grid()
            matches = self.matching_owned_rows(dialog, 'ip_rule')
            if matches:
                self.rule_created = True
                with self.ui(f'Reading firewall rule {self.rule_name}', self.ACTION_TIMEOUT_MS):
                    expiry = self.expiry_value(matches[0].locator("input[name='NetworkSecurityGroupRuleExpiration']").input_value(), 'ip_rule')
                self.firewall_expires_at = min(self.firewall_expires_at, expiry)
                self.close_dialog(dialog)
                self.screenshot('02_ip_rule')
                return
            self.close_dialog(dialog)
            if attempt < self.RULE_REFRESHES - 1:
                self._pause(self.RULE_REFRESH_PAUSE_SECONDS)
        raise AutomationError('ip_rule', f'Firewall rule {self.rule_name} did not appear in LCS after {self.RULE_REFRESHES} refreshes; check owned_rule.json and LCS.')

    def remove_owned_rule(self) -> None:
        if not self.rule_name:
            return
        manual = f'Remove firewall rule {self.rule_name} ({self.public_ip}) manually in LCS (Maintain > Enable access) if it is still listed.'
        # Discard unsubmitted/stale dialogs only after pending processing ends.
        # This also recovers cleanup after a failed add-dialog transition.
        self.refresh_environment()
        dialog = self.open_rule_grid()
        matches = self.matching_owned_rows(dialog, 'cleanup')
        if not matches:
            self.close_dialog(dialog)
            # A fresh, settled grid has confirmed absence (including natural expiry).
            self.rule_created = False
            return
        with self.ui(f'Selecting firewall rule {self.rule_name}', self.ACTION_TIMEOUT_MS, manual):
            for row in self.rule_rows(dialog).all():
                checkbox = row.get_by_role('checkbox')
                if checkbox.get_attribute('aria-checked') == 'true':
                    checkbox.click() # Only clears UI selection; never deletes other rows.
            checkbox = matches[0].get_by_role('checkbox')
            checkbox.click()
            selected = dialog.locator(".rowTemplate:not(.place-holder) [role='checkbox'][aria-checked='true']")
            if selected.count() != 1 or checkbox.get_attribute('aria-checked') != 'true':
                raise AutomationError('cleanup', 'Could not exclusively select owned firewall rule; refusing deletion.')
            self.safe_click(self.locator('rule_delete', scope=dialog))
        confirmation = self.page.get_by_role('dialog').filter(has=self.page.get_by_role('button', name='Yes', exact=True))
        try:
            confirmation.first.wait_for(state='visible', timeout=self.CONFIRM_TIMEOUT_MS)
        except BrowserError:
            pass # No confirmation shown: the fresh grid below decides.
        else:
            if confirmation.count() != 1:
                raise AutomationError('cleanup', f'More than one confirmation dialog is open; refusing to confirm the deletion. {manual}')
            with self.ui('The delete confirmation (Yes)', self.ACTION_TIMEOUT_MS, manual):
                self.safe_click(confirmation.get_by_role('button', name='Yes', exact=True))
        self.wait_idle()
        # Verify server state after a full refresh, not a stale in-place grid.
        self.refresh_environment()
        fresh = self.open_rule_grid()
        if self.matching_owned_rows(fresh, 'cleanup'):
            raise AutomationError('cleanup', f'Owned rule still present in freshly opened grid; deletion not confirmed. {manual}')
        self.close_dialog(fresh)
        self.rule_created = False
        self.screenshot('05_owned_rule_removed')

    @staticmethod
    def cell_value(locator: Locator) -> str:
        if locator.count() != 1:
            raise AutomationError('jit_request', 'A credential cell selector is missing or ambiguous.')
        tag = locator.evaluate('(el) => el.tagName.toLowerCase()')
        if tag in {'input', 'textarea'}:
            return locator.input_value().strip()
        return locator.inner_text().strip()

    def extract(self, old_rows: set[tuple[str, str, str, str]], requested_at: datetime) -> Credentials | None:
        accounts = self.locator('accounts')
        candidates: list[Credentials] = []
        for row in self.locator('rows', scope=accounts).all():
            if self.config.selectors.get('row_reason') and collapse(self.cell_value(self.locator('row_reason', scope=row))) != collapse(self.config.reason):
                continue
            if self.config.selectors.get('row_details') and collapse(self.cell_value(self.locator('row_details', scope=row))) != collapse(self.config.details):
                continue
            self.reveal_password(row)
            server_db = self.cell_value(self.locator('server_database', scope=row))
            username = self.cell_value(self.locator('username', scope=row))
            expiry_text = self.cell_value(self.locator('expires_at', scope=row))
            password = self.cell_value(self.locator('password', scope=row))
            # In-memory snapshot prevents silently reusing an unchanged old credential.
            if (server_db, username, expiry_text, password) in old_rows:
                continue
            if not password or is_masked(password):
                continue
            expiry = self.expiry_value(expiry_text, 'jit_request')
            server, database = parse_server_database(server_db, self.config.sql_dns_suffix)
            effective_expiry = min(expiry, self.firewall_expires_at, requested_at + timedelta(hours=8))
            if effective_expiry > utcnow() and username:
                candidates.append(Credentials(server, database, username, password, requested_at, effective_expiry))
        return max(candidates, key=lambda c: c.expires_at) if candidates else None

    def request_access(self) -> Credentials:
        self.step = 'jit_request'
        self.verify_environment()
        self.wait_idle()
        accounts = self.locator('accounts')
        old_rows: set[tuple[str, str, str, str]] = set()
        with self.ui('Reading the existing database accounts', self.ACTION_TIMEOUT_MS, 'Nothing was requested.'):
            for row in self.locator('rows', scope=accounts).all():
                self.reveal_password(row)
                old_rows.add((
                    self.cell_value(self.locator('server_database', scope=row)),
                    self.cell_value(self.locator('username', scope=row)),
                    self.cell_value(self.locator('expires_at', scope=row)),
                    self.cell_value(self.locator('password', scope=row)),
                ))
        with self.ui('The Request access form (reason and details)', self.ACTION_TIMEOUT_MS,
                     'Nothing was requested; check that your account can request database access for this environment.'):
            reason = self.locator('reason', scope=accounts)
            if reason.evaluate('(el) => el.tagName.toLowerCase()') == 'select':
                reason.select_option(label=self.config.reason)
            else:
                reason.click()
                self.locator('reason_list').get_by_role('option', name=self.config.reason, exact=True).click()
                if reason.input_value() != self.config.reason:
                    raise AutomationError('jit_request', 'Selected reason does not match configured access reason.')
            self.locator('details', scope=accounts).fill(self.config.details)
            self.locator('details', scope=accounts).press('Tab')
        self.requested_at = utcnow()
        with self.ui('The Request access button', self.ACTION_TIMEOUT_MS, 'Check LCS for a pending request before retrying.'):
            self.locator('request_access', scope=accounts).click()
        self.wait_idle()
        self.screenshot('03_jit_request')
        # Never retry the grant itself; only reload and read the already submitted request.
        deadline = time.monotonic() + self.CREDENTIAL_POLL_SECONDS
        wait = self.CREDENTIAL_FIRST_WAIT_SECONDS
        while True:
            self._pause(wait)
            wait = self.CREDENTIAL_POLL_INTERVAL_SECONDS
            with self.ui('Reloading the Database accounts section', self.NAVIGATION_TIMEOUT_MS,
                         'The request was submitted once; check LCS before requesting again.'):
                self.page.reload(wait_until='domcontentloaded', timeout=self.NAVIGATION_TIMEOUT_MS)
            if not self._wait_for_section(accounts):
                raise self._slow_section('The Database accounts section (after Request access was submitted once)')
            self.wait_idle()
            self.verify_environment()
            with self.ui('Reading the new database credential', self.ACTION_TIMEOUT_MS,
                         'The request was submitted once; check LCS before requesting again.'):
                credentials = self.extract(old_rows, self.requested_at)
            if credentials is not None:
                self.screenshot('04_credentials_masked')
                old_rows.clear()
                return credentials
            if time.monotonic() >= deadline:
                break
        raise AutomationError('jit_request', f'No new credential row appeared within {self.CREDENTIAL_POLL_SECONDS:g} s after Request access was submitted (once). '
                              'Check the request status in LCS; existing credentials are never reused silently.')

    @property
    def public_ip_source(self) -> str:
        return str(getattr(self, 'ip_source', '') or self.config.public_ip_source)

    def disable_ip(self) -> None:
        """Remove ONLY this run's source IP; not a claim of SQL credential revocation."""
        if not self.ip_rule_attempted:
            return
        self.step = 'cleanup'
        if self.config.selectors.get('rule_grid'):
            self.remove_owned_rule()
            return
        try:
            self.locator('maintain').click()
            self.locator('disable_access').click()
            dialog = self.locator('disable_dialog')
            dialog.wait_for(state='visible')
            self.locator('disable_ip_address', scope=dialog).fill(self.public_ip)
            self.locator('disable_submit', scope=dialog).click()
            dialog.wait_for(state='hidden', timeout=30000)
        except BrowserError:
            raise AutomationError('cleanup', 'IP removal could not be confirmed. Remove this host IP in LCS manually; SQL credentials may remain valid until expiry.') from None
