"""One stateful, bounded UI exploration pass after Katana."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
from typing import Callable

from aidast.core.http_safety import browser_has_authentication
from aidast.core.request_governor import GovernorError, RequestGovernor
from aidast.recon.tools.page_identity import canonical_visit_key, is_authentication_page_url
from aidast.ui_testing.agent import UIChoice, UIPlanner
from aidast.ui_testing.frontier import ExplorerFrontier, screen_key


@dataclass(frozen=True)
class ExplorerResult:
    pages: int
    screens: int
    actions: int
    decisions: int
    completed_forms: int
    eligible_forms: int
    blocked_forms: int
    new_endpoints: int
    frontier_remaining: int
    stop_reason: str


class StatefulUIExplorer:
    def __init__(self, planner: UIPlanner):
        self.planner = planner

    def run(self, driver, *, seed_urls: list[str], after_step: Callable[[], list[dict]],
            max_decisions: int = 50, max_seconds: float = 600) -> ExplorerResult:
        if type(max_decisions) is not int or not 1 <= max_decisions <= 100:
            raise ValueError('invalid decision limit')
        if not 0 < max_seconds <= 600:
            raise ValueError('invalid time limit')
        policy = driver.target_policy
        if policy is None or policy.request_governor is None:
            raise ValueError('UI exploration requires Scope and a shared governor')
        guarded = ((driver._browser_transport == 'proxy' and bool(driver.proxy_url))
                   or (driver._browser_transport == 'direct'
                       and driver._direct_workers_blocked is True))
        if not guarded:
            raise ValueError('UI exploration requires guarded browser transport')
        if (not (driver.preauthenticated or getattr(driver, '_operator_confirmed_login', False)
                 or getattr(driver, '_auth_checkpoint_state', None) is not None)
                or not browser_has_authentication(driver.get_auth_headers(),
                    identity_headers=policy.required_identity_headers)):
            raise ValueError('UI exploration requires an authenticated actor')

        deadline = time.monotonic() + max_seconds
        governor = RequestGovernor(policy.request_governor)
        frontier = ExplorerFrontier(max_pages=driver.interaction_config.max_pages)
        screens: set[str] = set()
        endpoints: set[tuple[str, str]] = set()
        pages = actions = decisions = completed_forms = 0
        current = driver._ensure_page().url

        def allowed_page(url: str) -> bool:
            parsed = urlparse(url)
            return bool(parsed.scheme in {'http', 'https'} and not parsed.username
                and not parsed.password and driver._same_origin(url)
                and policy.allows_url(url, method='GET')
                and not is_authentication_page_url(url)
                and not driver._path_looks_dangerous(parsed.path))

        def observe() -> list[dict]:
            rows = after_step()
            if not isinstance(rows, list):
                raise ValueError('invalid browser observation batch')
            for row in rows:
                if not isinstance(row, dict):
                    continue
                path = row.get('path')
                if not isinstance(path, str) or not path:
                    continue
                method = str(row.get('method', 'GET')).upper()
                endpoints.add((method, path))
                evidence = row.get('evidence') or {}
                status = evidence.get('response_status') if isinstance(evidence, dict) else None
                if (method == 'GET' and type(status) is int and 200 <= status < 300
                        and 'html' in str(row.get('content_type', '')).lower()):
                    url = urljoin(driver.base_url.rstrip('/') + '/', path)
                    if allowed_page(url):
                        frontier.add_page(url)
            return rows

        def result(reason: str, offered: list[dict] | None = None) -> ExplorerResult:
            eligible, blocked = driver.explorer_form_counts()
            remaining = frontier.queued_count + len(offered or [])
            if reason != 'frontier_exhausted':
                remaining = max(1, remaining)
            return ExplorerResult(pages, len(screens), actions, decisions,
                completed_forms, eligible, blocked, len(endpoints),
                remaining, reason)

        if not allowed_page(current):
            return result('policy_boundary')
        current_key = canonical_visit_key(current)
        if current_key not in driver._interaction_visited:
            if driver._interaction_page_count >= driver.interaction_config.max_pages:
                return result('page_limit')
            driver._interaction_visited.add(current_key)
            driver._interaction_page_count += 1
            pages += 1
        for url in seed_urls:
            if isinstance(url, str) and allowed_page(url):
                frontier.add_page(url)
        try:
            observe()
        except Exception:
            return result('observation_error')

        while True:
            if time.monotonic() >= deadline:
                return result('time_limit')
            if getattr(driver, '_auth_expired', False):
                return result('authentication_lost')
            current = driver._ensure_page().url
            if is_authentication_page_url(current):
                return result('authentication_lost')
            if not allowed_page(current):
                return result('policy_boundary')
            try:
                if governor.remaining_scan_requests() <= 0:
                    return result('request_limit')
            except GovernorError:
                return result('request_limit')

            inventory = driver.list_explorer_candidates()
            current_screen = screen_key(current, inventory)
            screens.add(current_screen)
            offered = frontier.untried(current_screen, inventory)[:60]
            if not offered and not inventory:
                hydration_end = min(deadline, time.monotonic() + 3)
                while time.monotonic() < hydration_end:
                    driver._ensure_page().wait_for_timeout(min(250, max(1, int(
                        (hydration_end - time.monotonic()) * 1000))))
                    current = driver._ensure_page().url
                    if not allowed_page(current):
                        return result('policy_boundary')
                    inventory = driver.list_explorer_candidates()
                    current_screen = screen_key(current, inventory)
                    screens.add(current_screen)
                    offered = frontier.untried(current_screen, inventory)[:60]
                    if offered:
                        break

            if offered:
                if decisions >= max_decisions:
                    return result('decision_limit', offered)
                context = {
                    'purpose': 'ordinary UI tasks',
                    'controls': [{'index': item['index'], 'label': item['label'],
                                  'kind': item['kind']} for item in offered],
                    'remaining_steps': max_decisions - decisions,
                    'remaining_seconds': max(0, deadline - time.monotonic()),
                }
                try:
                    choice = UIChoice.model_validate(self.planner.propose(context))
                except Exception:
                    return result('planner_error', offered)
                decisions += 1
                if time.monotonic() >= deadline:
                    return result('time_limit', offered)
                if choice.stop:
                    frontier.retire_screen(current_screen)
                    continue
                selected = next((item for item in offered
                                 if item['index'] == choice.candidate_index), None)
                if selected is None:
                    return result('invalid_choice', offered)
                frontier.mark_attempted(current_screen, selected['key'])
                try:
                    succeeded = driver.execute_explorer_candidate(
                        index=selected['index'], key=selected['key'],
                        screen=current_screen, deadline=deadline)
                except Exception:
                    succeeded = False
                actions += int(bool(succeeded))
                try:
                    observed_rows = observe()
                except Exception:
                    return result('observation_error')
                if succeeded and selected['kind'] == 'submit':
                    completed_forms += int(any(
                        str(row.get('method', '')).upper() == 'POST'
                        and isinstance(row.get('evidence'), dict)
                        and type(row['evidence'].get('response_status')) is int
                        and 200 <= row['evidence']['response_status'] < 300
                        for row in observed_rows if isinstance(row, dict)))
                new_url = driver._ensure_page().url
                if canonical_visit_key(new_url) not in driver._interaction_visited:
                    if driver._interaction_page_count >= driver.interaction_config.max_pages:
                        return result('page_limit')
                    driver._interaction_visited.add(canonical_visit_key(new_url))
                    driver._interaction_page_count += 1
                    pages += 1
                continue

            next_url = frontier.next_page()
            while next_url is not None and canonical_visit_key(next_url) in driver._interaction_visited:
                next_url = frontier.next_page()
            if next_url is None:
                return result('frontier_exhausted')
            if driver._interaction_page_count >= driver.interaction_config.max_pages:
                return result('page_limit')
            path = urlparse(next_url).path or '/'
            if urlparse(next_url).query:
                path += '?' + urlparse(next_url).query
            try:
                visited = driver.visit_path(path, timeout_ms=max(1, int((deadline - time.monotonic()) * 1000)))
            except Exception:
                visited = False
            try:
                observe()
            except Exception:
                return result('observation_error')
            if visited:
                key = canonical_visit_key(driver._ensure_page().url)
                if key not in driver._interaction_visited:
                    driver._interaction_visited.add(key)
                    driver._interaction_page_count += 1
                    pages += 1
