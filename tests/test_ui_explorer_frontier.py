"""The explorer frontier identifies screens and attempted UI actions."""

from aidast.ui_testing.frontier import ExplorerFrontier, screen_key


def test_same_screen_survives_dom_reorder_but_open_panel_is_new_screen():
    state = ExplorerFrontier(max_pages=30)
    initial = [
        {'index': 3, 'key': 'button:projects', 'kind': 'click', 'label': 'Projects'},
        {'index': 5, 'key': 'link:settings', 'kind': 'navigation', 'label': 'Settings'},
    ]
    reordered = [
        {'index': 17, 'key': 'link:settings', 'kind': 'navigation', 'label': 'Settings'},
        {'index': 19, 'key': 'button:projects', 'kind': 'click', 'label': 'Projects'},
    ]
    url = 'https://app.test/work?utm_source=campaign'
    first = screen_key(url, initial)
    assert first == screen_key('https://app.test/work', reordered)
    state.mark_attempted(first, 'button:projects')
    assert [item['key'] for item in state.untried(first, reordered)] == ['link:settings']

    with_panel = reordered + [
        {'index': 21, 'key': 'button:new-project', 'kind': 'click', 'label': 'New project'},
    ]
    assert screen_key(url, with_panel) != first


def test_retired_screen_and_bounded_page_queue():
    state = ExplorerFrontier(max_pages=2)
    assert state.add_page('https://app.test/work/a?utm_medium=email')
    assert not state.add_page('https://app.test/work/a')
    assert state.add_page('https://app.test/work/b')
    assert not state.add_page('https://app.test/work/c')
    assert state.queued_count == 2
    assert state.next_page() == 'https://app.test/work/a?utm_medium=email'
    assert state.next_page() == 'https://app.test/work/b'
    assert state.next_page() is None
    assert not state.add_page('https://app.test/work/a')

    candidate = {'index': 1, 'key': 'button:open', 'kind': 'click', 'label': 'Open'}
    state.retire_screen('screen-1')
    assert state.untried('screen-1', [candidate]) == []


def test_indistinguishable_candidate_keys_are_offered_once():
    state = ExplorerFrontier(max_pages=1)
    candidates = [
        {'index': 1, 'key': 'button:view', 'kind': 'click', 'label': 'View'},
        {'index': 2, 'key': 'button:view', 'kind': 'click', 'label': 'View'},
    ]
    assert [item['index'] for item in state.untried('screen', candidates)] == [1]
    state.mark_attempted('screen', 'button:view')
    assert state.untried('screen', candidates) == []
