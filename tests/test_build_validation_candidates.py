"""The lab inventory must preserve source claims without inventing Attack evidence."""

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.build_validation_candidates import (
    build_answer_key,
    build_inventory,
    build_inventory_pair,
    control_candidates,
    curated_vuln_bank_candidates,
    juice_candidates,
    vuln_bank_candidates,
)


def test_control_candidates_bind_to_pinned_source_without_verdicts() -> None:
    root = Path(__file__).resolve().parents[1]
    if not (root / "result/lab/vuln-bank").is_dir():
        pytest.skip("pinned local VulnBank checkout is not installed")
    server = (root / "resources/lab/juice-shop-v20.2.0-server.ts").read_text()
    bank = {name: (root / "result/lab/vuln-bank" / name).read_text()
            for name in ("app.py", "merchant_payments.py")}
    specs = json.loads((root / "resources/lab/validation-control-candidates.json").read_text())

    rows = control_candidates(specs, server, bank, vuln_commit="5e5ea5425fcf309373a0655dd111ecfb45037cbf")

    assert len(rows) == 8
    assert {project: sum(row["project"] == project for row in rows)
            for project in ("juice-shop", "vuln-bank")} == {"juice-shop": 4, "vuln-bank": 4}
    assert all(row["evaluation_status"] == "UNASSESSED" for row in rows)
    assert all("verdict" not in json.dumps(row).lower() for row in rows)
    with pytest.raises(ValueError, match="anchor"):
        control_candidates([{**specs[0], "anchor": "definitely absent"}], server, bank,
                           vuln_commit="5e5ea5425fcf309373a0655dd111ecfb45037cbf")
    with pytest.raises(ValueError, match="method"):
        control_candidates([{**specs[0], "method": "POST"}], server, bank,
                           vuln_commit="5e5ea5425fcf309373a0655dd111ecfb45037cbf")
    with pytest.raises(ValueError, match="verdict"):
        control_candidates([{**specs[0], "probe": {"expected_verdict": "NOT_VULNERABLE"}}],
                           server, bank,
                           vuln_commit="5e5ea5425fcf309373a0655dd111ecfb45037cbf")


def test_answer_key_is_separate_and_references_only_inventory_ids(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    bank_root = root / "result/lab/vuln-bank"
    if not bank_root.is_dir():
        pytest.skip("pinned local VulnBank checkout is not installed")
    names = ("app.py", "auth.py", "merchant_payments.py", "transaction_graphql.py", "README.md")
    sources = {name: (bank_root / name).read_text() for name in names}
    controls = json.loads((root / "resources/lab/validation-control-candidates.json").read_text())
    answers = json.loads((root / "resources/lab/validation-answer-key.json").read_text())
    inventory = tmp_path / "CandidateInventory.db"
    key = tmp_path / "CandidateAnswerKey.db"
    build_inventory(inventory, root / "resources/lab/juice-shop-v20.2.0-challenges.yml",
                    sources, vuln_commit="5e5ea5425fcf309373a0655dd111ecfb45037cbf",
                    curated_specs=json.loads((root / "resources/lab/vuln-bank-curated.json").read_text()),
                    control_specs=controls,
                    juice_server_source=root / "resources/lab/juice-shop-v20.2.0-server.ts")
    counts = build_answer_key(key, inventory, answers)

    assert counts == {"VULNERABLE": 2, "NOT_VULNERABLE": 8}
    assert {item["candidate_id"] for item in answers if item["expected_verdict"] == "NOT_VULNERABLE"} == {
        item["candidate_id"] for item in controls
    }
    with sqlite3.connect(inventory) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='answer_key'").fetchone() is None
        assert all("verdict" not in row[1].lower() for row in conn.execute("PRAGMA table_info(attack_candidates)"))
    with sqlite3.connect(key) as conn:
        assert conn.execute("SELECT COUNT(*) FROM answer_key").fetchone()[0] == sum(counts.values())
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        oracle = conn.execute(
            "SELECT expected_verdict,target_validation_status,readiness,COUNT(*) "
            "FROM answer_key GROUP BY 1,2,3 ORDER BY 1,2,3"
        ).fetchall()
        assert oracle == [
            ("NOT_VULNERABLE", "DISPROVEN", "GET_REPLAY_READY", 6),
            ("NOT_VULNERABLE", "DISPROVEN", "NEEDS_TWO_MERCHANT_IDENTITIES", 2),
            ("VULNERABLE", "CONFIRMED", "GET_REPLAY_READY", 1),
            ("VULNERABLE", "CONFIRMED", "NEEDS_TWO_MERCHANT_IDENTITIES", 1),
        ]
    with pytest.raises(ValueError, match="missing candidate"):
        build_answer_key(key, inventory, [{**answers[0], "candidate_id": "missing"}])
    with pytest.raises(ValueError, match="separate"):
        build_answer_key(inventory, inventory, answers)


def test_invalid_answer_does_not_replace_existing_inventory_pair(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    bank_root = root / "result/lab/vuln-bank"
    if not bank_root.is_dir():
        pytest.skip("pinned local VulnBank checkout is not installed")
    sources = {name: (bank_root / name).read_text()
               for name in ("app.py", "auth.py", "merchant_payments.py", "transaction_graphql.py", "README.md")}
    controls = json.loads((root / "resources/lab/validation-control-candidates.json").read_text())
    answers = json.loads((root / "resources/lab/validation-answer-key.json").read_text())
    curated = json.loads((root / "resources/lab/vuln-bank-curated.json").read_text())
    inventory = tmp_path / "CandidateInventory.db"
    key = tmp_path / "CandidateAnswerKey.db"
    arguments = (inventory, key, root / "resources/lab/juice-shop-v20.2.0-challenges.yml", sources)
    options = {"vuln_commit": "5e5ea5425fcf309373a0655dd111ecfb45037cbf",
               "curated_specs": curated, "control_specs": controls,
               "juice_server_source": root / "resources/lab/juice-shop-v20.2.0-server.ts"}
    build_inventory_pair(*arguments, answers, **options)
    before = (inventory.read_bytes(), key.read_bytes())

    with pytest.raises(ValueError, match="missing candidate"):
        build_inventory_pair(*arguments, [{**answers[0], "candidate_id": "missing"}], **options)

    assert (inventory.read_bytes(), key.read_bytes()) == before


def test_juice_challenges_keep_ids_and_docker_availability(tmp_path: Path) -> None:
    source = tmp_path / "challenges.yml"
    source.write_text(
        """- key: loginAdminChallenge
  name: Login Admin
  category: Injection
  description: Log in with an administrator account.
  difficulty: 2
- key: restfulXssChallenge
  name: API-only XSS
  category: XSS
  description: Perform a persisted XSS attack.
  difficulty: 3
  disabledEnv: [Docker]
""",
        encoding="utf-8",
    )

    rows = juice_candidates(source)

    assert [row["candidate_id"] for row in rows] == [
        "juice-shop:loginAdminChallenge", "juice-shop:restfulXssChallenge"
    ]
    assert rows[0]["vuln_class"] == "injection"
    assert rows[0]["endpoint_template"] is None
    assert rows[0]["readiness"] == "needs_route_mapping"
    assert rows[1]["availability"] == "disabled_in_docker"
    assert rows[1]["evaluation_status"] == "OUT_OF_TEST_SCOPE"


def test_non_security_juice_challenge_is_preserved_as_manual_only(tmp_path: Path) -> None:
    source = tmp_path / "challenges.yml"
    source.write_text(
        "- key: scoreBoardChallenge\n  name: Score Board\n"
        "  category: Miscellaneous\n  description: Find the board.\n",
        encoding="utf-8",
    )

    row = juice_candidates(source)[0]

    assert row["evaluation_status"] == "MANUAL_ONLY"


def test_vuln_bank_source_claims_bind_to_real_routes_and_ignore_fixed_notes() -> None:
    app = """from flask import Flask
app = Flask(__name__)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if True:
        # SQL Injection vulnerability
        pass
    # Debug info removed in v2
    return None

@app.route('/check_balance/<account_number>')
def balance(account_number):
    # Broken Object Level Authorization (BOLA) vulnerability
    return None
"""
    rows = vuln_bank_candidates({"app.py": app}, commit="a" * 40)

    assert {(row["endpoint_template"], row["method"], row["vuln_class"]) for row in rows} == {
        ("/login", "POST", "sql_injection"),
        ("/check_balance/<account_number>", "GET", "bola"),
    }
    assert all(row["source_url"].startswith(
        "https://github.com/Commando-X/vuln-bank/blob/" + "a" * 40
    ) for row in rows)
    assert next(row for row in rows if row["endpoint_template"] == "/login")[
        "route_source_url"
    ].endswith("/app.py#L3")
    assert all(row["readiness"] == "needs_reproduction_evidence" for row in rows)


def test_curated_bank_claim_requires_source_anchor_and_registered_route() -> None:
    sources = {"app.py": (
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/debug/users')\ndef users():\n"
        "    return {'password': 'example'}\n"
    )}
    spec = {"path": "/debug/users", "method": "GET", "vuln_class": "information_disclosure",
            "source_path": "app.py", "anchor": "return {'password': 'example'}",
            "description": "Debug endpoint exposes account data."}

    rows = curated_vuln_bank_candidates(sources, [spec], commit="a" * 40)

    assert len(rows) == 1
    assert rows[0]["source_line"] == 5
    assert rows[0]["claim_basis"] == "source_code"
    assert rows[0]["route_source_url"].endswith("/app.py#L3")
    with pytest.raises(ValueError, match="anchor"):
        curated_vuln_bank_candidates(sources, [{**spec, "anchor": "missing"}], commit="a" * 40)
    with pytest.raises(ValueError, match="route"):
        curated_vuln_bank_candidates(sources, [{**spec, "path": "/missing"}], commit="a" * 40)


def test_curated_code_anchor_in_unrelated_route_is_rejected() -> None:
    sources = {"app.py": (
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/first')\ndef first():\n    return None\n"
        "@app.route('/second')\ndef second():\n    # Vulnerability: SQL injection\n    return None\n"
    )}
    spec = {"path": "/first", "method": "GET", "vuln_class": "sql_injection",
            "source_path": "app.py", "anchor": "Vulnerability: SQL injection",
            "description": "Unrelated evidence."}

    with pytest.raises(ValueError, match="outside route"):
        curated_vuln_bank_candidates(sources, [spec], commit="a" * 40)


def test_rate_limit_claim_is_not_imported_when_route_has_a_rate_limit_decorator() -> None:
    app = """from flask import Flask
app = Flask(__name__)
@app.route('/api/ai/chat', methods=['POST'])
@ai_rate_limit
def chat():
    # VULNERABILITY: No rate limiting on AI calls
    return None
"""

    assert vuln_bank_candidates({"app.py": app}, commit="a" * 40) == []


def test_false_sqli_comments_on_integer_only_routes_do_not_become_candidates() -> None:
    app = """from flask import Flask
app = Flask(__name__)
@app.route('/api/billers/by-category/<int:category_id>')
def billers(category_id):
    # Vulnerability: SQL injection possible
    query = f'SELECT * FROM billers WHERE category_id = {category_id}'
    return query
@app.route('/api/virtual-cards/<int:card_id>/transactions')
def card_transactions(card_id):
    # Vulnerability: BOLA - no verification if card belongs to user
    # Vulnerability: SQL Injection possible
    query = f'SELECT * FROM transactions WHERE card_id = {card_id}'
    return query
"""

    rows = vuln_bank_candidates({"app.py": app}, commit="a" * 40)

    assert [(row["endpoint_template"], row["vuln_class"]) for row in rows] == [
        ("/api/virtual-cards/<int:card_id>/transactions", "bola")
    ]


def test_additional_authorization_check_comment_is_a_bola_lead() -> None:
    auth = """def routes(app):
    @app.route('/api/check_balance')
    def balance():
        # Vulnerability: No additional authorization check
        return None
"""

    rows = vuln_bank_candidates({"auth.py": auth}, commit="a" * 40)

    assert [(row["endpoint_template"], row["vuln_class"]) for row in rows] == [
        ("/api/check_balance", "bola")
    ]


def test_pinned_bank_checkout_has_expected_route_claims(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    bank = root / "result/lab/vuln-bank"
    if not bank.is_dir():
        pytest.skip("pinned local VulnBank checkout is not installed")
    source_names = ("app.py", "auth.py", "merchant_payments.py", "transaction_graphql.py", "README.md")
    sources = {name: (bank / name).read_text(encoding="utf-8") for name in source_names}
    specs = json.loads((root / "resources/lab/vuln-bank-curated.json").read_text(encoding="utf-8"))
    output = tmp_path / "CandidateInventory.db"

    build_inventory(output, root / "resources/lab/juice-shop-v20.2.0-challenges.yml",
                    sources, vuln_commit="5e5ea5425fcf309373a0655dd111ecfb45037cbf",
                    curated_specs=specs)

    with sqlite3.connect(output) as conn:
        found = set(conn.execute(
            "SELECT endpoint_template,method,vuln_class FROM attack_candidates WHERE project='vuln-bank'"
        ))
    assert ("/api/check_balance", "GET", "bola") in found
    assert ("/api/check_balance", "GET", "sql_injection") in found
    assert ("/debug/users", "GET", "excessive_data_exposure") in found
    assert ("/graphql", "POST", "graphql_introspection") in found
    assert ("/api/billers/by-category/<int:category_id>", "GET", "sql_injection") not in found
    assert ("/api/virtual-cards/<int:card_id>/transactions", "GET", "sql_injection") not in found


def test_inventory_rebuild_is_idempotent_and_never_creates_findings(tmp_path: Path) -> None:
    source = tmp_path / "challenges.yml"
    source.write_text(
        "- key: loginAdminChallenge\n  name: Login Admin\n"
        "  category: Injection\n  description: Log in.\n  difficulty: 2\n",
        encoding="utf-8",
    )
    output = tmp_path / "CandidateInventory.db"
    bank_source = {"app.py": (
        "from flask import Flask\napp=Flask(__name__)\n"
        "@app.route('/debug/users')\ndef users():\n"
        "    # Vulnerability: Information disclosure\n    return None\n"
    )}

    first = build_inventory(output, source, bank_source, vuln_commit="a" * 40)
    second = build_inventory(output, source, bank_source, vuln_commit="a" * 40)

    assert first == second == {"juice-shop": 1, "vuln-bank": 1}
    with sqlite3.connect(output) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='findings'").fetchone() is None
        rows = conn.execute(
            "SELECT candidate_id,source_url,source_sha256 FROM attack_candidates ORDER BY candidate_id"
        ).fetchall()
        assert [row[0] for row in rows] == [
            "juice-shop:loginAdminChallenge", "vuln-bank:app.py:GET:/debug/users:information_disclosure"
        ]
        assert all(row[1].startswith("https://github.com/") and len(row[2]) == 64 for row in rows)
        assert json.loads(conn.execute(
            "SELECT metadata_json FROM attack_candidates WHERE project='juice-shop'"
        ).fetchone()[0])["difficulty"] == 2


def test_duplicate_official_challenge_keys_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "challenges.yml"
    challenge = "- key: repeated\n  name: Repeat\n  category: XSS\n  description: Example\n"
    source.write_text(challenge * 2, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate"):
        juice_candidates(source)
