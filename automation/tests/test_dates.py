"""LCS expiry dates in any regional rendering; ambiguity never becomes a guess."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet

import lcs_jit_automation as lcs
from automation_support import AutomationError, Config, parse_lcs_datetime
from helpers import profile

NOW = datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc)


def utc(*parts):
    return datetime(*parts, tzinfo=timezone.utc)


@pytest.mark.parametrize(('text', 'expected', 'style'), [
    ('10/7/2026 4:12 PM', utc(2026, 10, 7, 16, 12), 'us_12h'),            # verified LCS format
    ('10/7/2026 4:26:05 PM', utc(2026, 10, 7, 16, 26, 5), 'us_12h'),
    ('10/17/2026 4:12 pm', utc(2026, 10, 17, 16, 12), 'us_12h'),
    ('17/10/2026 16:12', utc(2026, 10, 17, 16, 12), 'day_first_24h'),    # en-GB, day > 12
    ('07/10/2026 4:12 p.m.', utc(2026, 10, 7, 16, 12), 'day_first_12h'),  # en-IN: 7 Oct, July reading is past
    ('07.10.2026 16:12', utc(2026, 10, 7, 16, 12), 'day_first_24h'),     # de-DE
    ('2026/10/07 16:12', utc(2026, 10, 7, 16, 12), 'year_first_24h'),    # ja-JP
    ('2026-10-07T16:12:00', utc(2026, 10, 7, 16, 12), 'year_first_24h'),
    ('7/10/2026, 4:12\u202fPM', utc(2026, 10, 7, 16, 12), 'day_first_12h'),  # comma + narrow no-break space
    ('10/10/2026 4:12 PM', utc(2026, 10, 10, 16, 12), 'us_12h'),          # equal day and month
    ('9/30/2026 4:12 PM', utc(2026, 9, 30, 16, 12), 'us_12h'),            # expired, single reading
])
def test_regional_formats(text, expected, style):
    moment, matched, _ = parse_lcs_datetime(text, NOW)
    assert moment == expected
    assert matched == style


def test_known_page_order_breaks_ties():
    # 05/10 reads as 10 May (month-first) or 5 Oct (day-first); both are in the past.
    assert parse_lcs_datetime('05/10/2026 4:12 PM', NOW)[0] == utc(2026, 10, 5, 16, 12)  # latest reading
    assert parse_lcs_datetime('05/10/2026 4:12 PM', NOW, 'us_12h')[0] == utc(2026, 5, 10, 16, 12)
    assert parse_lcs_datetime('05/10/2026 4:12 PM', NOW, 'day_first_24h')[0] == utc(2026, 10, 5, 16, 12)


def test_ambiguous_far_future_and_garbage_fail_closed():
    with pytest.raises(ValueError):
        parse_lcs_datetime('11/12/2026 16:00', NOW)  # 12 Nov or 11 Dec, both beyond any LCS lifetime
    assert parse_lcs_datetime('tomorrow', NOW) is None


def adapter(step='jit_request'):
    instance = object.__new__(lcs.LCSAutomation)
    instance.config = MagicMock()
    instance.config.selectors = {'expiry_format': 'lcs_utc'}
    instance.step = step
    instance.lcs_date_format = ''
    instance.date_order_hint = ''
    return instance


def test_expiry_value_reports_shape_and_step_only():
    instance = adapter()
    with pytest.raises(AutomationError) as raised:
        instance.expiry_value('Thursday 7 October SECRET', 'ip_rule', NOW)
    assert raised.value.step == 'ip_rule'
    assert 'aaaaaaaa 9 aaaaaaa aaaaaa' in raised.value.message and 'SECRET' not in raised.value.message
    assert 'English (United States)' in raised.value.message
    with pytest.raises(AutomationError, match='ambiguous expiry date') as raised:
        instance.expiry_value('11/12/2026 16:00', 'cleanup', NOW)
    assert raised.value.step == 'cleanup'


def test_expiry_value_learns_order_from_unambiguous_dates():
    instance = adapter()
    assert instance.expiry_value('17/10/2026 16:12', now=NOW) == utc(2026, 10, 17, 16, 12)
    assert instance.lcs_date_format == 'day_first_24h'
    # Same page, ambiguous: read day-first like the unambiguous one.
    assert instance.expiry_value('05/10/2026 16:12', now=NOW) == utc(2026, 10, 5, 16, 12)


@pytest.mark.chromium
@pytest.mark.parametrize('persistent', [False, True])
def test_browser_is_pinned_to_en_us_and_utc(tmp_path, monkeypatch, persistent):
    from playwright.sync_api import sync_playwright
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    config = Config.load(profile(tmp_path))
    config.state_path = tmp_path / 'auth.enc'
    config.auth_key_path = tmp_path / 'auth.dpapi' if persistent else None
    config.state_path.write_bytes(lcs.cipher().encrypt(json.dumps({'cookies': [], 'origins': []}).encode()))
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        try:
            instance.context.route('https://lcs.dynamics.com/**', lambda route: route.fulfill(content_type='text/html', body='<p>x</p>'))
            instance.page.goto('https://lcs.dynamics.com/probe')
            facts = instance.page.evaluate('''() => ({language: navigator.language,
                zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                sample: new Date(Date.UTC(2026, 9, 7, 16, 12)).toLocaleString()})''')
        finally:
            instance.close()
    assert facts['language'] == 'en-US'
    assert facts['zone'] in {'UTC', 'Etc/UTC'}
    assert parse_lcs_datetime(facts['sample'].replace(',', ''), NOW)[0] == utc(2026, 10, 7, 16, 12)


def test_rows_that_existed_before_the_run_resolve_to_the_earlier_reading():
    # US page: 5/6 is 6 May (expired). Read on 5 June it must not become "valid until 16:12 today".
    june_fifth = datetime(2026, 6, 5, 10, 0, tzinfo=timezone.utc)
    assert parse_lcs_datetime('5/6/2026 4:12 PM', june_fifth)[0] == utc(2026, 6, 5, 16, 12)  # new row: latest
    assert parse_lcs_datetime('5/6/2026 4:12 PM', june_fifth, conservative=True)[0] == utc(2026, 5, 6, 16, 12)
    instance = adapter()
    assert instance.expiry_value('5/6/2026 4:12 PM', 'ip_rule', june_fifth, conservative=True) <= june_fifth


def test_symmetric_dates_do_not_teach_a_day_month_order():
    instance = adapter()
    instance.expiry_value('6/6/2026 4:12 PM', now=NOW)
    assert instance.date_order_hint == ''
    instance.expiry_value('10/17/2026 4:12 PM', now=NOW)
    assert instance.date_order_hint == 'month_first'
