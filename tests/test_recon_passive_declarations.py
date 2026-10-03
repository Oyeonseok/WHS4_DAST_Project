"""Passive declarations retain method/parameter evidence without sending requests."""
import json

import pytest

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder
from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools.passive_declarations import (
    declarations_from_captured_responses, declared_form_routes, declared_html_routes,
    declared_embedded_openapi_routes, declared_index_routes, declared_js_routes,
    declared_openapi_routes, inferred_openapi_routes, inferred_rest_resource_routes,
    inferred_runtime_configuration_routes,
)
from aidast.recon.policy import TargetPolicy
from aidast.recon.surface import export_surface
from aidast.scope.models import AssetType

BASE = "https://example.test/"


def js(script, **options):
    return declared_js_routes(script, document_url=BASE + "assets/main.js", base_url=BASE, **options)


def keys(rows):
    return {(row["method"], row["path"]) for row in rows}


def test_inline_form_fetch_combines_post_route_and_parameter_names():
    html = '''<form id="login"><input name="username"><input name="password"></form>
    <script>const data = new FormData(event.target); fetch('/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload) });</script>'''
    rows = declared_html_routes(html, document_url=BASE + "login", base_url=BASE)
    post = next(row for row in rows if row["method"] == "POST")
    assert post["path"] == "/login"
    assert post["declared_parameters"] == [
        {"name": "username", "location": "json", "data_type": "string"},
        {"name": "password", "location": "json", "data_type": "string"},
    ]


def test_durable_capture_reconciliation_recovers_html_js_and_openapi():
    rows = [
        (BASE + "login", "text/html; charset=utf-8",
         b'''<form><input name="username"><input name="password"></form>
         <script>const x=new FormData(event.target);fetch('/login',{method:'POST',
         headers:{'Content-Type':'application/json'},body:JSON.stringify(x)})</script>'''),
        (BASE + "app.js", "application/javascript", b"fetch('/api/items')"),
        (BASE + "openapi.json", "application/json", json.dumps({
            "openapi": "3.0.0",
            "paths": {"/api/pay": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"properties": {
                    "amount": {"type": "number"},
                }}},
            }}}}},
        }).encode()),
    ]
    found = declarations_from_captured_responses(rows, base_url=BASE)
    assert {("POST", "/login"), ("GET", "/api/items"), ("POST", "/api/pay")} <= keys(found)
    pay = next(row for row in found if row["path"] == "/api/pay")
    assert pay["declared_parameters"] == [
        {"name": "amount", "location": "json", "data_type": "number"}]


def test_swagger_ui_embedded_document_retains_server_and_write_method():
    script = 'var options = ' + json.dumps({"swaggerDoc": {
        "openapi": "3.0.0", "servers": [{"url": "/b2b/v2"}],
        "paths": {"/orders": {"post": {}}},
    }}) + '; window.ui = SwaggerUIBundle(options)'

    rows = declared_embedded_openapi_routes(
        script, document_url=BASE + "api-docs/swagger-ui-init.js", base_url=BASE,
    )

    assert keys(rows) == {("POST", "/b2b/v2/orders")}


def test_rest_resource_family_is_passively_inferred_from_declared_js_route():
    declared = js("client.put('/api/Products/' + product.id, payload)")

    rows = inferred_rest_resource_routes(declared, base_url=BASE)

    assert keys(rows) == {
        ("GET", "/api/Products"), ("POST", "/api/Products"),
        ("GET", "/api/Products/{id}"), ("PUT", "/api/Products/{id}"),
        ("PATCH", "/api/Products/{id}"), ("DELETE", "/api/Products/{id}"),
    }
    assert all(row["source"] == "passive_route_inference" for row in rows)
    assert all(row["verification_status"] == "candidate" for row in rows)
    assert all(row["traffic_class"] == "passive" for row in rows)
    assert all(row["evidence"]["derivation_rule"] == "rest_resource_family" for row in rows)


def test_durable_reconciliation_adds_rest_family_after_real_declarations():
    rows = [(BASE + "app.js", "application/javascript",
             "fetch('/api/Items'); client.delete('/api/Items/' + item.id)")]

    found = declarations_from_captured_responses(rows, base_url=BASE)

    assert keys(found) >= {
        ("GET", "/api/Items"), ("POST", "/api/Items"),
        ("GET", "/api/Items/{id}"), ("PUT", "/api/Items/{id}"),
        ("PATCH", "/api/Items/{id}"), ("DELETE", "/api/Items/{id}"),
    }


def test_rest_inference_rejects_nested_and_non_api_routes():
    declared = js("fetch('/api/admin/users'); fetch('/catalog/Products')")

    assert inferred_rest_resource_routes(declared, base_url=BASE) == []


def test_runtime_configuration_infers_enabled_public_metadata_routes():
    document = {"config": {"application": {
        "customMetricsPrefix": "service",
        "securityTxt": {"contact": "mailto:security@example.test"},
    }}}

    rows = inferred_runtime_configuration_routes(
        document, document_url=BASE + "runtime-config", base_url=BASE,
    )

    assert keys(rows) == {
        ("GET", "/metrics"), ("GET", "/security.txt"),
        ("GET", "/.well-known/security.txt"),
    }
    assert all(row["source"] == "passive_route_inference" for row in rows)
    assert all(row["verification_status"] == "candidate" for row in rows)


def test_runtime_configuration_requires_explicit_feature_values():
    assert inferred_runtime_configuration_routes(
        {"config": {"application": {"customMetricsPrefix": ""}}},
        document_url=BASE + "runtime-config", base_url=BASE,
    ) == []


def policy():
    return TargetPolicy(scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
        asset=BASE, allowed_hosts=["example.test"], allowed_ports=[443],
        allowed_schemes=["https"], allowed_methods=["GET"], allowed_path_prefixes=["/"],
        excluded_path_prefixes=["/private"])


def test_method_aware_js_request_shapes_and_named_route_templates():
    rows = js('''fetch("/api/pay", {method:"POST", body:payload});
        client.patch(`/profiles/${profile.userId}`, payload);
        axios({url:"/payments", method:"post", baseURL:"/v2"});
        axios.request({method:"DELETE", url:`/files/${fileId}`});
        fetch(new Request("/session", {method:"PUT"}));
        const xhr = new XMLHttpRequest(); xhr.open("POST", "/api/upload", true);
        axios("/activity"); fetch("/health");''')
    assert keys(rows) == {
        ("POST", "/api/pay"), ("PATCH", "/profiles/{userId}"), ("POST", "/v2/payments"),
        ("DELETE", "/files/{fileId}"), ("PUT", "/session"), ("POST", "/api/upload"),
        ("GET", "/activity"), ("GET", "/health"),
    }
    assert all(row["verification_status"] == "candidate" and row["traffic_class"] == "passive" for row in rows)
    assert all(row["evidence"]["source_scripts"] == [BASE + "assets/main.js"] for row in rows)


def test_public_js_request_bodies_contribute_names_and_types_without_values():
    rows = js('''const login={email:"person@example.test",password:secret,remember:true};
        client.post('/rest/user/login', login);
        client.patch('/api/profile', {displayName:name,age:21,tags:[],prefs:{}});
        fetch('/rest/2fa/verify', {method:'POST',
          body:JSON.stringify({tmpToken:token,totpToken:code})});
        axios({url:'/api/pay',method:'POST',data:{amount:1.5,note:'private'}});''')

    by_path = {row["path"]: row for row in rows}
    assert by_path["/rest/user/login"]["declared_parameters"] == [
        {"name": "email", "location": "json", "data_type": "string"},
        {"name": "password", "location": "json", "data_type": "string"},
        {"name": "remember", "location": "json", "data_type": "boolean"},
    ]
    assert by_path["/api/profile"]["declared_parameters"] == [
        {"name": "displayName", "location": "json", "data_type": "string"},
        {"name": "age", "location": "json", "data_type": "number"},
        {"name": "tags", "location": "json", "data_type": "array"},
        {"name": "prefs", "location": "json", "data_type": "object"},
    ]
    assert {item["name"] for item in by_path["/rest/2fa/verify"]["declared_parameters"]} == {
        "tmpToken", "totpToken",
    }
    assert {item["name"] for item in by_path["/api/pay"]["declared_parameters"]} == {
        "amount", "note",
    }
    assert "person@example.test" not in json.dumps(rows)
    assert "private" not in json.dumps(rows)


def test_opaque_service_body_uses_direct_public_object_callsite_fields() -> None:
    rows = js('''class UserService {
        resetPassword(e){return this.http.post(this.hostServer +
          '/rest/user/reset-password', e)}
      }
      component.resetPassword({email:privateEmail,answer:privateAnswer,
        new:privatePassword,repeat:privatePassword});''')

    reset = next(row for row in rows if row["path"] == "/rest/user/reset-password")
    assert {item["name"] for item in reset["declared_parameters"]} == {
        "email", "answer", "new", "repeat",
    }
    assert "private" not in json.dumps(rows)


def test_generic_service_method_does_not_merge_unrelated_callsites() -> None:
    rows = js('''class Service { save(e){return this.http.post(
        this.hostServer + '/api/Users', e)} }
      account.save({email:value}); orders.save({price:value});''')

    assert "declared_parameters" not in next(
        row for row in rows if row["path"] == "/api/Users"
    )


def test_body_binding_must_be_nearby_simple_object_and_never_executes_code():
    distant = "payload={accepted:true};" + "x" * 12_001 + ";"
    rows = js(distant + "client.post('/far',payload);"
              "client.post('/computed',makePayload());"
              "client.post('/near',{safe:value,...other});")

    assert keys(rows) == {("POST", "/far"), ("POST", "/computed"), ("POST", "/near")}
    assert all("declared_parameters" not in row for row in rows)


def test_literal_concatenated_urls_keep_declared_methods_and_complete_templates():
    rows = js('''fetch('/catalog/' + record.id + '/history');
        client.post('/payments/' + paymentId + '/capture', payload);
        axios({url:'/files/' + file.id, method:'DELETE'});
        const x = new XMLHttpRequest(); x.open('PUT', '/requests/' + request.uuid);
        new Request('/settings/' + person.name, {method:'PATCH'});
        fetch('/api/' + 'status');''')

    assert keys(rows) == {
        ("GET", "/catalog/{id}/history"), ("POST", "/payments/{paymentId}/capture"),
        ("DELETE", "/files/{id}"), ("PUT", "/requests/{uuid}"),
        ("PATCH", "/settings/{name}"), ("GET", "/api/status"),
    }
    assert all(row["verification_status"] == "candidate" and row["traffic_class"] == "passive"
               for row in rows)


def test_application_origin_prefixes_anchor_same_origin_routes():
    rows = js('''this.http.get(this.hostServer + '/rest/user/whoami' + query);
        this.http.post(`${config.apiUrl}/rest/2fa/verify`, payload);
        client.put(runtime.baseURL + '/api/Items/' + item.id, payload);''')

    assert keys(rows) == {
        ("GET", "/rest/user/whoami"), ("POST", "/rest/2fa/verify"),
        ("PUT", "/api/Items/{id}"),
    }


def test_nearby_same_origin_class_field_is_resolved_for_http_calls():
    rows = js('''class Wallet { hostServer = config.hostServer;
        host = this.hostServer + '/rest/wallet/balance';
        get() { return this.http.get(this.host); }
        put(value) { return this.http.put(this.host, value); }
        history() { return this.http.get(this.host + '/history'); } }''')

    assert keys(rows) == {
        ("GET", "/rest/wallet/balance"), ("PUT", "/rest/wallet/balance"),
        ("GET", "/rest/wallet/balance/history"),
    }


def test_method_local_route_derived_from_class_field_is_resolved():
    rows = js('''host = config.hostServer + '/rest/web3';
        submit() { let route = this.host + '/submitKey';
          return this.http.post(route, payload); }
        verify() { let route = this.host + '/walletNFTVerify';
          return this.http.post(route, payload); }''')

    assert keys(rows) == {
        ("POST", "/rest/web3/submitKey"),
        ("POST", "/rest/web3/walletNFTVerify"),
    }


def test_navigation_compiled_href_and_upload_config_are_declarations():
    rows = js('''window.location.replace(config.hostServer + '/profile');
        const attrs = ['href', './redirect?to=external'];
        uploader = new FileUploader({url: config.hostServer + '/file-upload',
          allowedMimeType: ['application/pdf'], maxFileSize: 1000});''')

    assert keys(rows) == {
        ("GET", "/profile"), ("GET", "/redirect"), ("POST", "/file-upload"),
    }


def test_distant_or_unanchored_class_field_is_not_resolved():
    distant = "host = config.hostServer + '/rest/old';" + "x" * 12_001
    assert js(distant + "this.http.get(this.host)") == []
    assert js("host = remoteServer + '/rest/private'; this.http.get(this.host)") == []


def test_incomplete_or_computed_url_concatenations_do_not_create_prefix_routes():
    rows = js('''fetch('/api/' + lookup(id), {method:'POST'});
        client.post('/prefix-' + id, payload); fetch(host + '/api/items');
        fetch('/api/' + null); fetch('/api/' + (id || fallback));
        axios({url:'/api/' + document['id'],method:'POST'});
        fetch('/valid/' + /* opaque identifier */ record.id, {method:'POST'});''')

    assert keys(rows) == {("POST", "/valid/{id}")}


def test_only_executable_inline_scripts_contribute_declared_calls():
    rows = declared_html_routes('''
        <script type="application/json">fetch('/json', {method:'POST'})</script>
        <script type="text/template">fetch('/template')</script>
        <script src="/bundle.js">fetch('/ignored')</script>
        <script type="MODULE">fetch('/module')</script>
        <script>fetch('/classic')</script>''', document_url=BASE, base_url=BASE)

    assert keys(rows) == {("GET", "/module"), ("GET", "/classic")}


def test_inactive_scripts_and_multiple_forms_do_not_supply_call_parameters():
    inactive = declared_html_routes('''<form action="/save" method="POST"><input name="user"></form>
        <script type="text/template">new FormData(event.target)</script>
        <script>fetch('/send', {method:'POST',body:payload})</script>''',
        document_url=BASE, base_url=BASE)
    assert "declared_parameters" not in next(row for row in inactive if row["path"] == "/send")

    ambiguous = declared_html_routes('''<form><input name="username"></form>
        <form><input name="contact"></form><script>
        const data=new FormData(event.target);fetch('/send',{method:'POST',body:data});</script>''',
        document_url=BASE, base_url=BASE)
    assert "declared_parameters" not in next(row for row in ambiguous if row["path"] == "/send")


def test_capture_duplicates_and_invalid_rows_do_not_consume_unique_route_limit():
    repeated = (BASE + "app.js", "text/javascript", "fetch('/catalog')")
    rows = [None, ("incomplete",), *([repeated] * 20),
            (BASE + "app.js", "text/javascript", "client.post('/orders', body)")]

    found = declarations_from_captured_responses(rows, base_url=BASE, limit=2)

    assert keys(found) == {("GET", "/catalog"), ("POST", "/orders")}


def test_capture_versions_merge_declared_parameters_even_at_route_limit():
    rows = [(BASE + "form", "text/html", f'<form action="/save" method="POST"><input name="{name}"></form>')
            for name in ["username", "password"]]

    found = declarations_from_captured_responses(rows, base_url=BASE, limit=1)

    assert keys(found) == {("POST", "/save")}
    assert {p["name"] for p in found[0]["declared_parameters"]} == {"username", "password"}


def test_later_document_declarations_have_priority_over_inferred_candidates():
    rows = [(BASE + "openapi.json", "application/json", json.dumps({
                "openapi": "3.0.0", "paths": {"/login": {"post": {}}}})),
            (BASE + "app.js", "text/javascript", "fetch('/catalog')")]

    found = declarations_from_captured_responses(rows, base_url=BASE, limit=2)

    assert keys(found) == {("POST", "/login"), ("GET", "/catalog")}
    assert all(row["source"] != "passive_route_inference" for row in found)


def test_external_oversized_and_malformed_captures_do_not_erase_later_declarations():
    rows = [("https://outside.test/app.js", "text/javascript", "fetch('/forged')"),
            (BASE + "large.js", "text/javascript", " " * (2 * 1024 * 1024 + 1)),
            (BASE + "openapi.json", "application/json", "[" * 2000),
            (BASE + "app.js", "text/javascript", "fetch('/valid')")]

    assert keys(declarations_from_captured_responses(rows, base_url=BASE)) == {("GET", "/valid")}


def test_js_nested_body_strings_comments_and_dynamic_methods_do_not_declare_routes():
    rows = js(r'''// axios({url:"/comment",method:"POST"});
        const re=/axios("\/regex")/;
        const config={url:"/unused",method:"POST"};
        fetch("/dynamic", {method: choice});
        axios({url:"/spread", method:"POST", ...other});
        fetch("/real", {method:"POST",body:{next:"/api/body-hint"}});
        const xhr=new XMLHttpRequest();xhr.open(dynamic,"/unknown");
        window.open("POST","/window");
        fetch(`/prefix-${id}`, {method:"POST"});
        axios({url:"/remote",baseURL:"https://outside.test"});''')
    assert keys(rows) == {("POST", "/real")}


@pytest.mark.parametrize("reference", [
    "https://outside.test/api/x", "https://user:pass@example.test/api/x",
    "/private/data", "/api/%2e%2e/internal", "/api/../internal",
    "/api/${fn()}", "${UNKNOWN}/route", "/api/%7Bid%7D", "api/relative",
])
def test_js_unsafe_or_ambiguous_references_are_skipped(reference):
    assert js(f'axios({{url:{json.dumps(reference)},method:"POST"}})', target_policy=policy()) == []


def test_query_values_and_credentials_are_discarded():
    rows = js('fetch("/search?q=private&token=hidden&limit=25")')
    assert rows[0]["url"] == BASE + "search?q=&limit="
    assert "private" not in json.dumps(rows) and "hidden" not in json.dumps(rows)


def test_forms_default_action_base_url_submitter_overrides_and_field_names():
    rows = declared_form_routes('''<base href="/account/">
        <input form="profile" name="detached" value="not retained">
        <form id="profile" action="save" method="POST">
          <input name="user_id" value="private"><input type="password" name="password" value="secret">
          <input disabled name="disabled"><textarea name="bio">personal text</textarea>
          <button formaction="preview" formmethod="GET">Preview</button>
        </form><form><input name="q" value="search"></form>''',
        document_url=BASE + "profile/edit", base_url=BASE)
    assert keys(rows) == {("POST", "/account/save"), ("GET", "/account/preview"), ("GET", "/profile/edit")}
    save = next(row for row in rows if row["method"] == "POST")
    assert {(p["name"], p["location"]) for p in save["declared_parameters"]} == {
        ("user_id", "form"), ("password", "form"), ("bio", "form"), ("detached", "form")}
    assert "secret" not in json.dumps(rows) and "personal text" not in json.dumps(rows)
    assert all(row["verification_status"] == "candidate" for row in rows)


def test_forms_external_base_and_dialog_are_skipped_but_default_action_is_document():
    rows = declared_form_routes('''<base href="https://outside.test/">
        <form action="submit" method="POST"></form><form method="dialog"></form>
        <form method="POST"></form>''', document_url=BASE + "form", base_url=BASE)
    assert keys(rows) == {("POST", "/form")}


def test_malformed_form_action_does_not_discard_other_forms():
    rows = declared_form_routes('<form action="http://[invalid" method="POST"></form><form method="POST" action="/valid"></form>',
        document_url=BASE + "form", base_url=BASE)
    assert keys(rows) == {("POST", "/valid")}


def test_openapi_all_methods_templates_parameters_and_server_overrides_are_passive():
    document = {"openapi": "3.1.0", "servers": [{"url": "/v1"}], "paths": {
        "/users/{user_id}": {"parameters": [{"in": "path", "name": "user_id", "schema": {"type": "integer"}}],
            "get": {"parameters": [{"in": "query", "name": "expand", "required": True}]},
            "post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {
                "display_name": {"type": "string"}, "active": {"type": "boolean"}}}}}}}},
        "/items": {"servers": [{"url": "/v2"}], "patch": {}},
        "/ref": {"$ref": "https://outside.test/openapi.json#/paths/~1ref"},
    }}
    rows = declared_openapi_routes(document, document_url=BASE + "docs/openapi.json", base_url=BASE)
    assert keys(rows) == {("GET", "/v1/users/{user_id}"), ("POST", "/v1/users/{user_id}"), ("PATCH", "/v2/items")}
    post = next(row for row in rows if row["method"] == "POST")
    assert {(p["name"], p["location"], p["data_type"]) for p in post["declared_parameters"]} == {
        ("user_id", "path", "integer"), ("display_name", "json", "string"), ("active", "json", "boolean")}


def test_passive_openapi_maps_external_canonical_server_to_document_origin():
    document = {"openapi": "3.0.0", "servers": [{"url": "https://production.test"}],
                "paths": {"/payments": {"get": {}, "post": {}}}}
    rows = declared_openapi_routes(
        document, document_url=BASE + "static/openapi.json", base_url=BASE,
    )

    assert keys(rows) == {("GET", "/payments"), ("POST", "/payments")}
    assert all(row["verification_status"] == "candidate" for row in rows)
    assert all(row["evidence"]["server_scope_fallback"] is True for row in rows)


def test_passive_openapi_expands_bounded_declared_path_enums_without_requests():
    document = {"openapi": "3.0.0", "paths": {
        "/api/v{version}/reset": {"post": {"parameters": [{
            "name": "version", "in": "path", "required": True,
            "schema": {"type": "integer", "enum": [1, 2, 3]},
        }]}}
    }}
    rows = declared_openapi_routes(
        document, document_url=BASE + "openapi.json", base_url=BASE,
    )

    assert keys(rows) == {
        ("POST", "/api/v1/reset"), ("POST", "/api/v2/reset"),
        ("POST", "/api/v3/reset"),
    }
    assert all(row["evidence"]["path_enum_expansion"] is True for row in rows)


def test_openapi_route_family_inference_is_bounded_passive_and_evidence_based():
    document = {"openapi": "3.0.0", "paths": {
        "/login": {"post": {"tags": ["authentication"], "summary": "Log in"}},
        "/api/v2/reset-password": {"post": {
            "tags": ["authentication"], "summary": "Reset password"}},
        "/api/v1/merchants/register": {"post": {
            "tags": ["authentication"], "summary": "Register merchant"}},
        "/latest/meta-data/": {"get": {}},
    }}
    rows = inferred_openapi_routes(
        document, document_url=BASE + "openapi.json", base_url=BASE,
    )

    assert {("POST", "/api/login"), ("GET", "/reset-password"),
            ("POST", "/reset-password"), ("GET", "/merchant"),
            ("GET", "/merchant/dashboard"), ("GET", "/merchant/register"),
            ("GET", "/latest/meta-data/hostname")} <= keys(rows)
    assert all(row["source"] == "passive_route_inference" for row in rows)
    assert all(row["verification_status"] == "candidate" for row in rows)
    assert all(row["evidence"].get("derivation_rule") for row in rows)
    assert inferred_openapi_routes(document, document_url=BASE + "openapi.json",
                                    base_url=BASE, limit=2) == rows[:2]


def test_declarations_tolerate_malformed_parameter_entries_and_enforce_limits():
    document = {"openapi": "3.0.0", "paths": {f"/route/{i}": {"post": {
        "parameters": [{"name": "x", "in": {}, "schema": {"type": []}}, None],
        "requestBody": {"content": []}}} for i in range(50)}}
    rows = declared_openapi_routes(document, document_url=BASE + "openapi.json", base_url=BASE, limit=3)
    assert len(rows) == 3 and all("declared_parameters" not in row for row in rows)
    assert js('fetch("/one");fetch("/two")', limit=1)[0]["path"] == "/one"
    assert js('fetch("/one")', limit=0) == []


def test_captured_robots_and_sitemaps_are_inventoried_without_following_links():
    robots = declared_index_routes('''User-agent: *\nDisallow: /restricted\nAllow: /public
        Disallow: /wild/*\nSitemap: https://example.test/site.xml\nSitemap: https://outside.test/site.xml''',
        document_url=BASE + "robots.txt", base_url=BASE)
    assert keys(robots) == {("GET", "/restricted"), ("GET", "/public"), ("GET", "/site.xml")}
    sitemap = declared_index_routes('''<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://example.test/catalog</loc></url><url><loc>https://outside.test/x</loc></url></urlset>''',
        document_url=BASE + "site.xml", base_url=BASE)
    assert keys(sitemap) == {("GET", "/catalog")}
    assert declared_index_routes('<!DOCTYPE x [<!ENTITY a "expanded">]><urlset/>',
        document_url=BASE + "site.xml", base_url=BASE) == []


def test_adaptive_captured_form_discovery_works_without_scripts_or_requests(monkeypatch):
    monkeypatch.setattr(secondary, "_http_request", lambda *_a, **_k: pytest.fail("passive form made a request"))
    capture = dict(method="GET", url=BASE + "profile", capture_bodies=True, response_status=200,
        response_headers={"content-type": "text/html"}, response_body='<form method="POST" action="/save"></form>')
    rows = secondary.discover_adaptive_js_api_candidates(BASE, [{"method": "GET", "path": "/profile"}],
        observed_responses=[capture], include_passive_writes=True)
    assert keys(rows) == {("POST", "/save")}


def test_authentication_identity_does_not_mix_passive_documents(monkeypatch):
    monkeypatch.setattr(secondary, "_http_request", lambda *_a, **_k: pytest.fail("wrong session made a request"))
    capture = dict(method="GET", url=BASE + "profile", capture_bodies=True, response_status=200,
        request_headers={"Cookie": "session=other"}, response_headers={"content-type": "text/html"},
        response_body='<form method="POST" action="/save"></form>')
    rows = secondary.discover_adaptive_js_api_candidates(BASE, [],
        observed_responses=[capture], include_passive_writes=True)
    assert rows == []


def test_new_js_request_shapes_are_never_added_to_active_probes(monkeypatch):
    requested = []
    def request(url, **_options):
        requested.append(url)
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'axios({url:"/write",method:"POST"});const x=new XMLHttpRequest();x.open("GET","/declared-only");'
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "application/json"}, b'{}'
        pytest.fail(f"passive declaration made a request: {url}")
    monkeypatch.setattr(secondary, "_http_request", request)
    rows = secondary.discover_adaptive_js_api_candidates(BASE, [{"path": "/main.js"}], include_passive_writes=True)
    assert keys(rows) == {("POST", "/write"), ("GET", "/declared-only")}
    assert all(row["verification_status"] == "candidate" for row in rows)


def test_secondary_openapi_templates_and_writes_survive_unavailable_zap_without_requests(monkeypatch):
    specification = {"openapi": "3.0.0", "paths": {"/items/{item_id}": {"get": {}, "post": {}}}}
    monkeypatch.setattr(secondary, "detect_openapi", lambda *_a, **_k: [secondary.OpenAPIDefinition(document=specification)])
    monkeypatch.setattr(secondary, "detect_graphql", lambda *_a, **_k: [])
    monkeypatch.setattr(secondary, "_run_zap", lambda *_a, **_k: False)
    monkeypatch.setattr(secondary, "_http_request", lambda *_a, **_k: pytest.fail("template made a request"))
    rows = secondary.discover_api_secondary(BASE, [], target_policy=policy(), proxy_url="http://127.0.0.1:8888")
    assert keys(rows) == {
        ("GET", "/items/{item_id}"), ("POST", "/items/{item_id}"),
        ("GET", "/api/items"), ("GET", "/api/items/{item_id}"),
        ("POST", "/api/items/{item_id}"),
    }
    assert all(row["verification_status"] == "candidate" for row in rows)


def test_verified_openapi_get_keeps_declared_query_parameter_names(monkeypatch):
    specification = {"openapi": "3.0.0", "paths": {"/items": {"get": {
        "parameters": [{"name": "filter", "in": "query", "schema": {"type": "string"}}]}}}}
    monkeypatch.setattr(secondary, "detect_openapi", lambda *_a, **_k: [secondary.OpenAPIDefinition(document=specification)])
    monkeypatch.setattr(secondary, "detect_graphql", lambda *_a, **_k: [])
    monkeypatch.setattr(secondary, "_run_zap", lambda *_a, **_k: False)
    monkeypatch.setattr(secondary, "_http_request", lambda url, **_k: (
        (200, {"content-type": "application/json"}, b'{"items":[]}') if url.endswith("/items") else
        (404, {"content-type": "application/json"}, b'{"error":"missing"}')))
    rows = secondary.discover_api_secondary(BASE, [], target_policy=policy(), proxy_url="http://127.0.0.1:8888")
    verified = next(row for row in rows if row["path"] == "/items")
    assert verified["verification_status"] == "verified"
    assert verified["declared_parameters"] == [{"name": "filter", "location": "query", "data_type": "string"}]
    assert next(row for row in rows if row["path"] == "/api/items")["verification_status"] == "candidate"


def test_form_candidates_and_parameter_names_persist_without_becoming_verified_surface(tmp_path):
    rows = declared_form_routes('<form action="/users" method="POST"><input name="user_id" value="42"><input name="password" value="secret"></form>',
        document_url=BASE + "register", base_url=BASE)
    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value=BASE)
        asset = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(connection, asset_id=asset, scheme="https", host="example.test", port=443, base_url=BASE)
        ObservationRecorder(connection, origin_id=origin, scan_id="scan").record("passive", rows)
        assert connection.execute("SELECT verification_status,is_excluded,exclude_reason FROM endpoints").fetchone() == (
            "candidate", 1, "unverified_candidate")
        parameters = connection.execute("SELECT name,location,role,example_value FROM parameters ORDER BY name").fetchall()
        assert parameters == [("password", "form", "credential", None), ("user_id", "form", "identifier", None)]
        surface = json.loads(export_surface(connection, scan_id="scan", output_path=tmp_path / "Surface.json").read_text())
        assert surface["origins"][0]["endpoints"] == []
        assert surface["origins"][0]["candidate_endpoints"][0]["method"] == "POST"
        assert "secret" not in json.dumps(surface)
