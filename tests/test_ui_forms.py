from aidast.ui_testing.forms import synthetic_value


def test_project_name_uses_only_scan_id_and_never_field_text():
    field = {'type': 'text', 'role': 'project_name', 'label': 'Project secret=abc'}
    assert synthetic_value(field, 'scan_project') == 'AI-Dast-scanproject'


def test_sensitive_or_unclassified_fields_have_no_generated_value():
    assert synthetic_value({'type': 'password', 'role': 'project_name'}, 'scan') is None
    assert synthetic_value({'type': 'file', 'role': 'project_name'}, 'scan') is None
    assert synthetic_value({'type': 'text', 'role': 'unknown'}, 'scan') is None


def test_search_uses_bounded_literal():
    assert synthetic_value({'type': 'search', 'role': 'search'}, 'scan') == 'test'
