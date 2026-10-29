"""The README that messages and launchers point to must exist and agree with them."""
from __future__ import annotations

import re
from pathlib import Path

from helpers import APP, ROOT

README = ROOT / 'README.md'
# Files whose messages or links send users to README.md#<anchor>.
REFERRING = sorted(APP.glob('*.py')) + sorted(APP.glob('*.yaml')) + [
    APP / 'setup.ps1', APP / 'run.cmd', APP / 'README.md', ROOT / 'run.ps1', ROOT / 'run.cmd',
]
FENCE = re.compile(r'\s*(```|~~~)')


def read(path: Path) -> str:
    return path.read_text(encoding='utf-8-sig')


def github_slug(heading: str) -> str:
    """GitHub's heading anchor: lowercase, punctuation except - and _ removed, spaces as hyphens."""
    return re.sub(r'[^\w\- ]', '', heading.strip().lower()).replace(' ', '-')


def readme_anchors() -> set[str]:
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    fenced = False
    for line in read(README).splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        match = None if fenced else re.match(r'#{1,6}\s+(.+?)\s*#*\s*$', line)
        if match:
            slug = github_slug(match.group(1))
            seen = counts.get(slug, 0)
            counts[slug] = seen + 1
            anchors.add(slug if seen == 0 else f'{slug}-{seen}')
    return anchors


def section(text: str, heading: str) -> str:
    match = re.search(rf'^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)', text, re.M | re.S)
    assert match, f'README.md has no "## {heading}" section'
    return match.group(1)


def test_slug_matches_github_for_the_heading_styles_used() -> None:
    assert github_slug('First-time setup and repeat runs') == 'first-time-setup-and-repeat-runs'
    assert github_slug('1. Download and extract the project') == '1-download-and-extract-the-project'
    assert github_slug('Proxies and certificates') == 'proxies-and-certificates'


def test_every_readme_anchor_in_messages_and_launchers_exists() -> None:
    anchors = readme_anchors()
    referenced = {(path.relative_to(ROOT).as_posix(), anchor)
                  for path in REFERRING for anchor in re.findall(r'README\.md#([A-Za-z0-9_-]+)', read(path))}
    assert len({anchor for _, anchor in referenced}) >= 5  # The scan found the references.
    missing = sorted(f'{name} -> README.md#{anchor}' for name, anchor in referenced if anchor not in anchors)
    assert not missing, f'README.md has no heading for: {missing}'


def test_readme_links_point_to_existing_files_and_headings() -> None:
    anchors = readme_anchors()
    broken: list[str] = []
    for document in (README, APP / 'README.md'):
        for target in re.findall(r'\]\(([^)\s]+)\)', read(document)):
            if re.match(r'[A-Za-z][A-Za-z0-9+.-]*:', target):
                continue  # https: and other absolute links
            path_part, _, anchor = target.partition('#')
            resolved = (document.parent / path_part).resolve() if path_part else document
            if not resolved.exists():
                broken.append(f'{document.relative_to(ROOT).as_posix()}: {target} (no such file)')
            elif anchor and resolved == README and anchor not in anchors:
                broken.append(f'{document.relative_to(ROOT).as_posix()}: {target} (no such heading)')
    assert not broken


def test_no_instruction_points_at_the_automation_readme() -> None:
    """automation/README.md only links to the root README, where the instructions are."""
    offenders = [path.relative_to(ROOT).as_posix() for path in [README, *REFERRING]
                 if re.search(r'automation[/\\]README\.md', read(path), re.I)]
    assert not offenders


def test_launcher_options_table_lists_every_run_ps1_parameter() -> None:
    params = re.search(r'^param\((.*?)^\)', read(ROOT / 'run.ps1'), re.M | re.S)
    assert params, 'run.ps1 has no param() block'
    names = re.findall(r'\[(?:switch|string)\]\$(\w+)', params.group(1))
    assert 'Config' in names and 'ValidateOnly' in names
    rows = [line for line in section(read(README), 'Launcher options').splitlines() if line.startswith('|')]
    missing = [name for name in names if not any(re.search(rf'`\.\\run\.cmd -{name}\b', row) for row in rows)]
    assert not missing, f'README.md#launcher-options does not list: {missing}'


def test_compatibility_wrapper_flags_are_documented() -> None:
    flags = re.findall(r'"%~1"=="(--[a-z-]+)"', read(APP / 'run.cmd'))
    assert '--config' in flags and '--validate-only' in flags
    options = section(read(README), 'Launcher options')
    missing = [flag for flag in flags if not re.search(rf'`{re.escape(flag)}(?: <path>)?`', options)]
    assert not missing, f'README.md#launcher-options does not list: {missing}'
