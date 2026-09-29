"""Literal URL joins must keep the whole path and the HTTP method evidence."""
import pytest

from aidast.recon.tools.js_api_paths import extract_js_api_paths, literal_call_method


@pytest.mark.parametrize('script,want', [
    ('http.get("/reports/" + "daily")', [('/reports/daily', 'GET')]),
    ('fetch("/api/" + "records" + "/recent")', [('/api/records/recent', 'GET')]),
    (r'http.get("/reports" /*join*/ + `\/daily`)', [('/reports/daily', 'GET')]),
    ('class C{host="/reports"+"/daily";r(){http.get(this.host+"/summary")}}',
     [('/reports/daily/summary', 'GET')]),
    ('class C{host="/reports"+"/daily";r(){http.get(`${this.host}/summary`)}}',
     [('/reports/daily/summary', 'GET')]),
    ('fetch("/reports/"+"write", {method:"POST"})', []),
    ('http.get("https://outside.test"+"/reports/daily")', []),
    ('http.get("/reports/"+"daily"+unknown)', []),
    ('http.get("/reports/"+"daily"||unknown)', []),
    ('class C{host="/reports"+"/daily"+unknown;r(){http.get(this.host+"/summary")}}', []),
    ('http.get(unknown+"/reports/"+"daily")', []),
    ('http.get(("/reports/"+"daily")+unknown)', []),
    ('http.get(unknown+("/reports/"+"daily"))', []),
    ('class C{host=unknown+"/reports"+"/daily";r(){http.get(this.host+"/summary")}}', []),
])
def test_static_join_preserves_complete_path_and_method(script, want):
    assert extract_js_api_paths(script, literal_call_method) == want


def test_long_unresolved_join_does_not_repeatedly_rescan_suffixes():
    import subprocess
    import sys
    script = '''from aidast.recon.tools.js_api_paths import extract_js_api_paths, literal_call_method
source = 'http.get("/reports/"+' + '"x"+' * 10000 + 'unknown)'
assert extract_js_api_paths(source, literal_call_method) == []
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, timeout=2)
    assert result.returncode == 0, result.stderr.decode()


def test_many_adjacent_comments_do_not_rescan_remaining_comments():
    import subprocess
    import sys
    script = '''from aidast.recon.tools.js_api_paths import extract_js_api_paths, literal_call_method
source = '/*x*/' * 10000 + 'unknown'
assert extract_js_api_paths(source, literal_call_method) == []
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, timeout=2)
    assert result.returncode == 0, result.stderr.decode()
