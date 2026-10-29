"""LCS browser adapter. All selectors require tenant validation; no MFA bypass."""
from __future__ import annotations

import ipaddress
import json
import os
import time
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

from automation_support import (AutomationError, Config, Credentials, LCS_HOSTS, date_shape, default_rule_name, describe_error, parse_expiry,
                                parse_lcs_datetime, parse_server_database, timestamp, utcnow)

BROWSER_CHANNEL = 'chromium'  # Full Chromium for headless and visible runs (no headless shell).
BROWSER_LOCALE = 'en-US'
BROWSER_LAUNCH_TIMEOUT_MS = 120000  # First start can be slow while security software scans.

LCS_URL = 'https://lcs.dynamics.com'
LOGIN_HOSTS = {'login.microsoftonline.com', 'login.live.com', 'login.windows.net'}


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
            self.context.set_default_timeout(10000)
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
                    with self.page.expect_navigation(wait_until='domcontentloaded', timeout=30000):
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
            self.page.goto(target_url, wait_until='domcontentloaded', timeout=30000)

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

    def navigate(self, *, allow_interactive_auth: bool = False) -> None:
        self.step = 'authentication'
        origin_url = self.config.lcs_origin
        url = self.config.environment_url or f'{origin_url}/V2/Project/{self.config.project_id}/'
        for attempt in range(3):
            try:
                self.page.goto(url, wait_until='domcontentloaded', timeout=30000)
                self._complete_lcs_landing(url)
                if self.config.environment_url:
                    self.locator('accounts').wait_for(state='visible', timeout=30000)
                    self.verify_environment()
                    save_auth(self.context, self.config.state_path, self.config.auth_key_path)
                    self.screenshot('01_login')
                    return
                self.locator('environment_link').wait_for(state='visible', timeout=30000)
                if not self.page.url.startswith(origin_url + '/'):
                    raise AutomationError('authentication', 'Authentication expired or MFA/Conditional Access requires interaction. Run bootstrap on this trusted host.')
                save_auth(self.context, self.config.state_path, self.config.auth_key_path)
                self.screenshot('01_login')
                self.locator('environment_link').click()
                self.locator('accounts').wait_for(state='visible', timeout=30000)
                self.verify_environment()
                return
            except AutomationError as auth_error:
                if allow_interactive_auth and auth_error.step == 'authentication':
                    self.bootstrap(navigate_first=False)
                    self.screenshot('01_login')
                    return
                raise
            except BrowserError:
                from urllib.parse import urlsplit
                origin = urlsplit(self.page.url).hostname
                if origin in LOGIN_HOSTS or not self.page.url.startswith(origin_url + '/'):
                    if allow_interactive_auth:
                        self.bootstrap(navigate_first=False)
                        self.screenshot('01_login')
                        return
                    if origin in LOGIN_HOSTS:
                        raise AutomationError('authentication', 'Saved login requires sign-in/MFA. Run ./run.ps1 -ForceInteractive.') from None
                if self.page.url.startswith(origin_url + '/') and self.page.get_by_role('button', name='Maintain', exact=True).count():
                    raise AutomationError('environment', f'Environment not found in project {self.config.project_id}; check ENVIRONMENT_ID and environment_link selector.') from None
                if attempt < 2:
                    time.sleep(2 ** attempt)
        if self.page.url.startswith(origin_url + '/'):
            raise AutomationError('environment', f'Environment not found in project {self.config.project_id}; check permissions and environment_link selector.')
        if allow_interactive_auth:
            self.bootstrap(navigate_first=False)
            self.screenshot('01_login')
            return
        raise AutomationError('authentication', 'Login failed after three attempts. Re-run bootstrap; Entra MFA/Conditional Access cannot be bypassed.')

    def bootstrap(self, *, navigate_first: bool = True) -> None:
        origin_url = self.config.lcs_origin
        target_url = self.config.environment_url or f'{origin_url}/V2/Project/{self.config.project_id}/'
        if navigate_first:
            self.page.goto(target_url, wait_until='domcontentloaded', timeout=30000)
        if self.config.environment_url:
            print('Complete sign-in and MFA; wait for the environment page to load, then press Enter here.', file=sys.stderr)
            input()
            self._complete_lcs_landing(target_url)
            if not self.page.url.startswith(origin_url + '/'):
                raise AutomationError('authentication', 'Sign in and open the configured environment before saving authentication.')
            try:
                self.locator('accounts').wait_for(state='visible', timeout=30000)
                self.page.locator('h1').wait_for(state='visible', timeout=30000)
                self.verify_environment()
                self.wait_idle()
            except BrowserError:
                raise AutomationError('environment', 'Environment heading does not match ENVIRONMENT_ID; refusing to save authentication.') from None
        else:
            print('Complete sign-in and MFA in the browser; open the project, then press Enter here.', file=sys.stderr)
            input()
            self._complete_lcs_landing(target_url)
            if not self.page.url.startswith(f'{origin_url}/V2/Project/{self.config.project_id}'):
                raise AutomationError('authentication', 'Open the configured LCS project before saving authentication.')
            self.locator('environment_link').wait_for(state='visible', timeout=30000)
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
                dialog.wait_for(state='hidden', timeout=30000)
                self.screenshot('02_ip_rule')
                return
            except BrowserError:
                if attempt == 0:
                    time.sleep(2)
        raise AutomationError('ip_rule', 'IP rule could not be confirmed. Check dialog selectors, LCS permissions, and existing IP rules.')

    def wait_idle(self, timeout: int = 120000) -> None:
        """Wait for LCS async request processing to finish before UI actions."""
        try:
            # #ShellBlockingDiv is LCS's full-screen pointer-event interceptor;
            # it has no layout only while no async request is in flight.
            self.page.wait_for_function(
                "() => { const block = document.querySelector('#ShellBlockingDiv');"
                " const blocked = block && block.getClientRects().length > 0;"
                " const text = Array.from(document.querySelectorAll('.applicationShell-blockingMessageText'))"
                " .some(el => el.getClientRects().length && /processing|please wait/i.test(el.innerText));"
                " return !blocked && !text; }",
                timeout=timeout)
        except BrowserError:
            raise AutomationError(self.step, 'LCS did not finish processing within the allowed time; no further UI changes attempted.') from None

    def safe_click(self, locator: Locator, timeout: int = 15000) -> None:
        """Respect visibility/enabled/overlay checks; never dispatch forced JS clicks."""
        self.wait_idle()
        locator.click(timeout=timeout)

    def close_dialog(self, dialog: Locator) -> None:
        self.wait_idle()
        if dialog.is_visible():
            self.safe_click(self.locator('rule_close', scope=dialog))
            dialog.wait_for(state='hidden', timeout=15000)

    def refresh_environment(self) -> None:
        """Reload only after processing completes; discard stale LCS modal layers."""
        self.wait_idle()
        self.page.reload(wait_until='domcontentloaded', timeout=30000)
        self.locator('accounts').wait_for(state='visible', timeout=30000)
        self.wait_idle()
        self.verify_environment()

    def open_rule_grid(self) -> Locator:
        self.wait_idle()
        dialog = self.locator('enable_dialog')
        if not dialog.is_visible():
            self.safe_click(self.locator('maintain'))
            self.safe_click(self.locator('enable_access'))
        dialog.wait_for(state='visible', timeout=30000)
        self.locator('rule_grid', scope=dialog).wait_for(state='visible')
        self.page.wait_for_function("() => !Array.from(document.querySelectorAll('[role=dialog] [role=grid]')).some(el => el.getAttribute('aria-busy') === 'true')")
        # The Dynamics grid shell appears before its asynchronous rows are bound.
        self.page.wait_for_timeout(2000)
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
        password = self.cell_value(self.locator('password', scope=row))
        if password and set(password) <= {'*', '•', '●'}:
            self.locator('password_reveal', scope=row).click()

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
        self.locator('rule_add', scope=dialog).click()
        add = self.locator('rule_add_dialog')
        add.wait_for(state='visible')
        self.page.wait_for_function("() => Array.from(document.querySelectorAll('[role=dialog] input[name=Services]')).some(el => el.value === 'AzureSQL')", timeout=15000)
        # Service is left at the LCS default; do not click, fill or change it.
        add.locator("input[name='NameField']").fill(self.rule_name)
        add.locator("input[name='IpOrCidrField']").fill(public_ip)
        add.locator("input[name='IpOrCidrField']").press('Tab')
        self.ip_rule_attempted = True
        # Persist no secrets: retain a recovery record before changing firewall access.
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / 'owned_rule.json').write_text(json.dumps({'name': self.rule_name, 'public_ip': public_ip, 'environment_id': self.config.environment_id, 'created_at': timestamp(utcnow())}), encoding='utf-8')
        self.locator('rule_confirm', scope=add).click()
        add.wait_for(state='hidden', timeout=180000)
        self.wait_idle()
        # LCS leaves a non-dialog popupShadow/modalBackground layer after add.
        # Reload after processing instead of forcing a click through that layer.
        self.refresh_environment()
        dialog = self.open_rule_grid()
        for _ in range(30):
            matches = self.matching_owned_rows(dialog, 'ip_rule')
            if matches:
                self.rule_created = True
                expiry = self.expiry_value(matches[0].locator("input[name='NetworkSecurityGroupRuleExpiration']").input_value(), 'ip_rule')
                self.firewall_expires_at = min(self.firewall_expires_at, expiry)
                self.close_dialog(dialog)
                self.screenshot('02_ip_rule')
                return
            time.sleep(1)
        raise AutomationError('ip_rule', 'New owned firewall rule could not be confirmed; check owned_rule.json and LCS.')

    def remove_owned_rule(self) -> None:
        if not self.rule_name:
            return
        # Discard unsubmitted/stale dialogs only after pending processing ends.
        # This also recovers cleanup after a failed add-dialog transition.
        self.refresh_environment()
        dialog = self.open_rule_grid()
        matches = self.matching_owned_rows(dialog, 'cleanup')
        if not matches:
            self.close_dialog(dialog)
            # A fresh grid has confirmed absence (including natural expiry).
            self.rule_created = False
            return
        rows = self.rule_rows(dialog)
        for row in rows.all():
            checkbox = row.get_by_role('checkbox')
            if checkbox.get_attribute('aria-checked') == 'true':
                checkbox.click() # Only clears UI selection; never deletes other rows.
        checkbox = matches[0].get_by_role('checkbox')
        checkbox.click()
        selected = dialog.locator(".rowTemplate:not(.place-holder) [role='checkbox'][aria-checked='true']")
        if selected.count() != 1 or checkbox.get_attribute('aria-checked') != 'true':
            raise AutomationError('cleanup', 'Could not exclusively select owned firewall rule; refusing deletion.')
        self.locator('rule_delete', scope=dialog).click()
        self.page.wait_for_timeout(1000)
        confirmation = self.page.get_by_role('dialog').filter(has=self.page.get_by_role('button', name='Yes', exact=True))
        if confirmation.count() == 1 and confirmation.is_visible():
            self.safe_click(confirmation.get_by_role('button', name='Yes', exact=True))
        self.wait_idle()
        # Verify server state after a full refresh, not a stale in-place grid.
        self.refresh_environment()
        fresh = self.open_rule_grid()
        if self.matching_owned_rows(fresh, 'cleanup'):
            raise AutomationError('cleanup', 'Owned rule still present in freshly opened grid; deletion not confirmed.')
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
            if self.config.selectors.get('row_reason') and self.cell_value(self.locator('row_reason', scope=row)) != self.config.reason:
                continue
            if self.config.selectors.get('row_details') and self.cell_value(self.locator('row_details', scope=row)) != self.config.details:
                continue
            self.reveal_password(row)
            server_db = self.cell_value(self.locator('server_database', scope=row))
            username = self.cell_value(self.locator('username', scope=row))
            expiry_text = self.cell_value(self.locator('expires_at', scope=row))
            password = self.cell_value(self.locator('password', scope=row))
            # In-memory snapshot prevents silently reusing an unchanged old credential.
            if (server_db, username, expiry_text, password) in old_rows:
                continue
            if not password or set(password) <= {'*', '•', '●'}:
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
        for row in self.locator('rows', scope=accounts).all():
            self.reveal_password(row)
            old_rows.add((
                self.cell_value(self.locator('server_database', scope=row)),
                self.cell_value(self.locator('username', scope=row)),
                self.cell_value(self.locator('expires_at', scope=row)),
                self.cell_value(self.locator('password', scope=row)),
            ))
        try:
            reason = self.locator('reason', scope=accounts)
            if reason.evaluate('(el) => el.tagName.toLowerCase()') == 'select':
                reason.select_option(label=self.config.reason)
            else:
                reason.click()
                self.locator('reason_list').get_by_role('option', name=self.config.reason, exact=True).click()
                if reason.input_value() != self.config.reason:
                    raise AutomationError('jit_request', 'Selected reason does not match configured access reason.')
            self.locator('details', scope=accounts).fill(self.config.details)
            self.requested_at = utcnow()
            self.locator('details', scope=accounts).press('Tab')
            self.locator('request_access', scope=accounts).click()
            self.wait_idle()
            self.screenshot('03_jit_request')
            for attempt in range(2):
                # Never retry a grant POST blindly; only reload/poll the already submitted request.
                time.sleep(5 if attempt == 0 else 10)
                self.page.reload(wait_until='domcontentloaded', timeout=30000)
                self.locator('accounts').wait_for(state='visible', timeout=15000)
                self.wait_idle()
                self.verify_environment()
                credentials = self.extract(old_rows, self.requested_at)
                if credentials is not None:
                    self.screenshot('04_credentials_masked')
                    old_rows.clear()
                    return credentials
        except BrowserError:
            raise AutomationError('jit_request', 'JIT request UI failed. Verify access reason, selectors, permissions, and active authentication.') from None
        raise AutomationError('jit_request', 'No new unmasked, unexpired credential row after refresh. Inspect selectors and request status; existing credentials are not silently reused.')

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
