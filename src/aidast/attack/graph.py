"""Durable, sanitized online Attack graph projected from Pipeline.db evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable
from uuid import uuid4


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _identifier(prefix: str, *parts: str) -> str:
    return prefix + "_" + hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:32]


@dataclass(frozen=True)
class GraphSyncResult:
    scan_id: str
    revision_id: str | None
    graph_sha256: str
    nodes: int
    edges: int
    nodes_added: int
    nodes_changed: int
    edges_added: int
    edges_changed: int

    @property
    def changed(self) -> bool:
        return bool(self.revision_id)


class _Projector:
    def __init__(self, conn: sqlite3.Connection, scan_id: str, stage_run_id: str | None):
        self.conn = conn
        self.scan_id = scan_id
        self.stage_run_id = stage_run_id
        self.nodes_added = 0
        self.nodes_changed = 0
        self.edges_added = 0
        self.edges_changed = 0

    def _event(
        self, kind: str, *, node_id: str | None = None, edge_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.conn.execute(
            """INSERT INTO attack_graph_events
               (event_id,scan_id,stage_run_id,node_id,edge_id,event_kind,details_json)
               VALUES (?,?,?,?,?,?,?)""",
            (
                "graph_event_" + uuid4().hex, self.scan_id, self.stage_run_id,
                node_id, edge_id, kind, _json(details or {}),
            ),
        )

    def node(
        self, kind: str, key: str, *, state: str = "active", priority: int = 50,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        node_id = _identifier("graph_node", self.scan_id, kind, key)
        document = metadata or {}
        content = _digest([state, priority, document])
        row = self.conn.execute(
            "SELECT content_sha256 FROM attack_graph_nodes WHERE node_id=?", (node_id,),
        ).fetchone()
        if row is None:
            self.conn.execute(
                """INSERT INTO attack_graph_nodes
                   (node_id,scan_id,node_kind,node_key,state,priority,metadata_json,content_sha256)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (node_id, self.scan_id, kind, key, state, priority, _json(document), content),
            )
            self.nodes_added += 1
            self._event("node.added", node_id=node_id, details={"kind": kind})
        elif row[0] != content:
            self.conn.execute(
                """UPDATE attack_graph_nodes
                   SET state=?,priority=?,metadata_json=?,content_sha256=?,updated_at=CURRENT_TIMESTAMP
                   WHERE node_id=?""",
                (state, priority, _json(document), content, node_id),
            )
            self.nodes_changed += 1
            self._event("node.changed", node_id=node_id, details={"kind": kind})
        return node_id

    def edge(
        self, source: str, target: str, relationship: str, *, state: str = "active",
        evidence: dict[str, Any] | None = None,
    ) -> str:
        edge_id = _identifier(
            "graph_edge", self.scan_id, source, target, relationship,
        )
        document = evidence or {}
        content = _digest([state, document])
        row = self.conn.execute(
            "SELECT content_sha256 FROM attack_graph_edges WHERE edge_id=?", (edge_id,),
        ).fetchone()
        if row is None:
            self.conn.execute(
                """INSERT INTO attack_graph_edges
                   (edge_id,scan_id,from_node_id,to_node_id,relationship,state,
                    evidence_json,content_sha256)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (edge_id, self.scan_id, source, target, relationship, state,
                 _json(document), content),
            )
            self.edges_added += 1
            self._event("edge.added", edge_id=edge_id, details={"relationship": relationship})
        elif row[0] != content:
            self.conn.execute(
                """UPDATE attack_graph_edges
                   SET state=?,evidence_json=?,content_sha256=?,updated_at=CURRENT_TIMESTAMP
                   WHERE edge_id=?""",
                (state, _json(document), content, edge_id),
            )
            self.edges_changed += 1
            self._event("edge.changed", edge_id=edge_id,
                        details={"relationship": relationship})
        return edge_id


def _rows(conn: sqlite3.Connection, sql: str, parameters: Iterable[object]) -> list[sqlite3.Row]:
    return list(conn.execute(sql, tuple(parameters)).fetchall())


def synchronize_attack_graph(
    conn: sqlite3.Connection, scan_id: str, *, stage_run_id: str | None = None,
    trigger_kind: str = "evidence.changed",
) -> GraphSyncResult:
    """Project durable DB evidence and create a planner revision only on change.

    Raw response bodies, credential URIs, tokens, and fact values are deliberately
    excluded. The graph contains stable references and evidence shapes only.
    """
    conn.row_factory = sqlite3.Row
    projector = _Projector(conn, scan_id, stage_run_id)
    endpoint_nodes: dict[str, str] = {}
    for row in _rows(conn, """SELECT e.endpoint_id,e.method,e.normalized_path,e.auth_required,
                                      e.verification_status
                               FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
                               JOIN assets a ON a.asset_id=o.asset_id
                               WHERE a.scan_id=? AND e.is_excluded=0
                               ORDER BY e.endpoint_id""", (scan_id,)):
        endpoint_nodes[row["endpoint_id"]] = projector.node(
            "endpoint", row["endpoint_id"], priority=60,
            metadata={
                "endpoint_id": row["endpoint_id"], "method": row["method"],
                "normalized_path": row["normalized_path"],
                "auth_required": bool(row["auth_required"]),
                "verification_status": row["verification_status"],
            },
        )
    for row in _rows(conn, """SELECT p.parameter_id,p.endpoint_id,p.name,p.location,p.role,
                                      p.data_type,p.is_identifier
                               FROM parameters p JOIN endpoints e ON e.endpoint_id=p.endpoint_id
                               JOIN origins o ON o.origin_id=e.origin_id
                               JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=?
                               ORDER BY p.parameter_id""", (scan_id,)):
        endpoint = endpoint_nodes.get(row["endpoint_id"])
        if endpoint is None:
            continue
        parameter = projector.node(
            "parameter", row["parameter_id"], priority=45,
            metadata={key: row[key] for key in (
                "parameter_id", "endpoint_id", "name", "location", "role", "data_type",
            )} | {"is_identifier": bool(row["is_identifier"])},
        )
        projector.edge(endpoint, parameter, "accepts_parameter")

    coverage_nodes: dict[str, str] = {}
    for row in _rows(conn, """SELECT coverage_id,endpoint_id,vuln_class,skill_name,status,
                                      required_identity_role,attempt_count,finding_id
                               FROM attack_coverage_items WHERE scan_id=?
                               ORDER BY coverage_id""", (scan_id,)):
        state = (
            "resolved" if row["status"] in {
                "tested_negative", "candidate", "confirmed", "policy_excluded", "unsupported",
                "error_terminal",
            } else "blocked" if row["status"] == "blocked_auth"
            else "running" if row["status"] == "running" else "queued"
        )
        priority = 85 if row["status"] in {"candidate", "error_retryable"} else 55
        coverage = projector.node(
            "coverage", row["coverage_id"], state=state, priority=priority,
            metadata={key: row[key] for key in (
                "coverage_id", "endpoint_id", "vuln_class", "skill_name", "status",
                "required_identity_role", "attempt_count", "finding_id",
            )},
        )
        coverage_nodes[row["coverage_id"]] = coverage
        endpoint = endpoint_nodes.get(row["endpoint_id"])
        if endpoint:
            projector.edge(endpoint, coverage, "has_coverage_hypothesis")

    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='attack_preconditions'"
    ).fetchone():
        for row in _rows(conn, """SELECT p.precondition_id,p.coverage_id,p.kind,p.state,
                                          p.resolution_reference_type,
                                          a.action_id,a.action_kind,a.status action_status
                                   FROM attack_preconditions p
                                   LEFT JOIN attack_operator_actions a
                                     ON a.precondition_id=p.precondition_id
                                   WHERE p.scan_id=? ORDER BY p.precondition_id""", (scan_id,)):
            precondition = projector.node(
                "precondition", row["precondition_id"],
                state=("satisfied" if row["state"] == "satisfied" else
                       "retired" if row["state"] == "retired" else "blocked"),
                priority=90 if row["state"] == "required" else 40,
                metadata={key: row[key] for key in (
                    "precondition_id", "coverage_id", "kind", "state",
                    "resolution_reference_type", "action_id", "action_kind",
                    "action_status",
                )},
            )
            coverage = coverage_nodes.get(row["coverage_id"])
            if coverage:
                projector.edge(coverage, precondition, "requires_precondition")

    finding_nodes: dict[str, str] = {}
    for row in _rows(conn, """SELECT finding_id,endpoint_id,vuln_type,severity,title,status
                               FROM findings WHERE scan_id=? ORDER BY finding_id""", (scan_id,)):
        finding = projector.node(
            "finding", row["finding_id"], priority=100,
            state="resolved" if row["status"] in {"rejected", "resolved"} else "active",
            metadata={key: row[key] for key in (
                "finding_id", "endpoint_id", "vuln_type", "severity", "title", "status",
            )},
        )
        finding_nodes[row["finding_id"]] = finding
        endpoint = endpoint_nodes.get(row["endpoint_id"])
        if endpoint:
            projector.edge(endpoint, finding, "produced_finding")

    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='attack_chain_leads'"
    ).fetchone():
        for row in _rows(conn, """SELECT chain_lead_id,source_finding_id,
                                          followup_coverage_id,relationship,state,priority
                                   FROM attack_chain_leads WHERE scan_id=?
                                   ORDER BY chain_lead_id""", (scan_id,)):
            chain = projector.node(
                "chain", row["chain_lead_id"], state=(
                    "resolved" if row["state"] == "completed" else
                    "running" if row["state"] == "running" else "queued"
                ), priority=int(row["priority"]),
                metadata={key: row[key] for key in (
                    "chain_lead_id", "source_finding_id", "followup_coverage_id",
                    "relationship", "state", "priority",
                )},
            )
            source = finding_nodes.get(row["source_finding_id"])
            followup = coverage_nodes.get(row["followup_coverage_id"])
            if source:
                projector.edge(source, chain, "opens_chain_branch")
            if followup:
                projector.edge(chain, followup, "schedules_followup")

    for row in _rows(conn, """SELECT a.attempt_id,a.endpoint_id,a.skill_name,a.outcome,
                                      a.finding_id,a.resolved_at,a.task_id
                               FROM attack_attempts a WHERE a.scan_id=? AND a.outcome='lead'
                               ORDER BY a.attempt_id""", (scan_id,)):
        lead = projector.node(
            "lead", row["attempt_id"], priority=95,
            state="resolved" if row["resolved_at"] or row["finding_id"] else "active",
            metadata={key: row[key] for key in (
                "attempt_id", "endpoint_id", "skill_name", "outcome", "finding_id", "task_id",
            )},
        )
        endpoint = endpoint_nodes.get(row["endpoint_id"])
        if endpoint:
            projector.edge(endpoint, lead, "produced_lead")
        finding = finding_nodes.get(row["finding_id"])
        if finding:
            projector.edge(lead, finding, "promoted_to")

    for row in _rows(conn, """SELECT fact_id,fact_type,fact_key,confidence,
                                      source_endpoint_id,source_finding_id
                               FROM attack_facts WHERE scan_id=? ORDER BY fact_id""", (scan_id,)):
        kind = "object" if row["fact_type"] == "owned_test_object" else (
            "identity" if row["fact_type"] in {"session", "identity", "role"} else "fact"
        )
        fact = projector.node(
            kind, row["fact_id"], priority=90 if kind in {"object", "identity"} else 70,
            metadata={key: row[key] for key in (
                "fact_id", "fact_type", "fact_key", "confidence",
                "source_endpoint_id", "source_finding_id",
            )},
        )
        endpoint = endpoint_nodes.get(row["source_endpoint_id"])
        if endpoint:
            projector.edge(endpoint, fact, "observed_fact")
        finding = finding_nodes.get(row["source_finding_id"])
        if finding:
            projector.edge(finding, fact, "established_fact")

    role_nodes: dict[str, str] = {}
    for row in _rows(conn, """SELECT credential_reference_id,label,identity_role,session_id
                               FROM credential_references WHERE scan_id=?
                               ORDER BY credential_reference_id""", (scan_id,)):
        credential = projector.node(
            "credential", row["credential_reference_id"], priority=90,
            metadata={key: row[key] for key in (
                "credential_reference_id", "label", "identity_role", "session_id",
            )},
        )
        role = role_nodes.setdefault(
            row["identity_role"],
            projector.node("role", row["identity_role"], priority=75,
                           metadata={"identity_role": row["identity_role"]}),
        )
        projector.edge(credential, role, "grants_role")

    node_rows = _rows(conn, """SELECT node_id,content_sha256 FROM attack_graph_nodes
                                WHERE scan_id=? ORDER BY node_id""", (scan_id,))
    edge_rows = _rows(conn, """SELECT edge_id,content_sha256 FROM attack_graph_edges
                                WHERE scan_id=? ORDER BY edge_id""", (scan_id,))
    graph_sha256 = _digest([
        [(row["node_id"], row["content_sha256"]) for row in node_rows],
        [(row["edge_id"], row["content_sha256"]) for row in edge_rows],
    ])
    prior = conn.execute(
        "SELECT revision_id FROM attack_graph_revisions WHERE scan_id=? AND graph_sha256=?",
        (scan_id, graph_sha256),
    ).fetchone()
    revision_id = None
    if prior is None:
        revision_id = _identifier("graph_revision", scan_id, graph_sha256)
        conn.execute(
            """INSERT INTO attack_graph_revisions
               (revision_id,scan_id,stage_run_id,trigger_kind,graph_sha256,node_count,edge_count)
               VALUES (?,?,?,?,?,?,?)""",
            (revision_id, scan_id, stage_run_id, trigger_kind, graph_sha256,
             len(node_rows), len(edge_rows)),
        )
        projector._event(
            "planner.revision", details={
                "revision_id": revision_id, "trigger_kind": trigger_kind,
                "graph_sha256": graph_sha256, "node_count": len(node_rows),
                "edge_count": len(edge_rows),
            },
        )
    return GraphSyncResult(
        scan_id=scan_id, revision_id=revision_id, graph_sha256=graph_sha256,
        nodes=len(node_rows), edges=len(edge_rows), nodes_added=projector.nodes_added,
        nodes_changed=projector.nodes_changed, edges_added=projector.edges_added,
        edges_changed=projector.edges_changed,
    )


def graph_context_for_endpoint(
    conn: sqlite3.Connection, scan_id: str, endpoint_id: str, *, limit: int = 32,
) -> dict[str, Any]:
    """Return a bounded reference-only neighborhood for the next Attack batch."""
    if not 1 <= limit <= 128:
        raise ValueError("graph context limit must be between 1 and 128")
    endpoint = conn.execute(
        """SELECT node_id FROM attack_graph_nodes
           WHERE scan_id=? AND node_kind='endpoint' AND node_key=?""",
        (scan_id, endpoint_id),
    ).fetchone()
    if endpoint is None:
        return {"revision_id": None, "nodes": [], "edges": []}
    revision = conn.execute(
        """SELECT revision_id FROM attack_graph_revisions
           WHERE scan_id=? ORDER BY rowid DESC LIMIT 1""",
        (scan_id,),
    ).fetchone()
    node_rows = conn.execute(
        """SELECT DISTINCT n.node_id,n.node_kind,n.node_key,n.state,n.priority,n.metadata_json
           FROM attack_graph_nodes n
           LEFT JOIN attack_graph_edges e ON e.scan_id=n.scan_id AND
             (e.from_node_id=n.node_id OR e.to_node_id=n.node_id)
           WHERE n.scan_id=? AND (n.node_id=? OR e.from_node_id=? OR e.to_node_id=?)
           ORDER BY n.priority DESC,n.node_kind,n.node_id LIMIT ?""",
        (scan_id, endpoint[0], endpoint[0], endpoint[0], limit),
    ).fetchall()
    node_ids = [row["node_id"] for row in node_rows]
    edges: list[dict[str, Any]] = []
    if node_ids:
        placeholders = ",".join("?" for _ in node_ids)
        edges = [dict(row) for row in conn.execute(
            f"""SELECT edge_id,from_node_id,to_node_id,relationship,state
                FROM attack_graph_edges WHERE scan_id=? AND
                (from_node_id IN ({placeholders}) OR to_node_id IN ({placeholders}))
                ORDER BY relationship,edge_id LIMIT ?""",
            (scan_id, *node_ids, *node_ids, limit * 2),
        )]
    return {
        "revision_id": revision[0] if revision else None,
        "nodes": [{
            "node_id": row["node_id"], "kind": row["node_kind"],
            "key": row["node_key"], "state": row["state"],
            "priority": row["priority"], "metadata": json.loads(row["metadata_json"]),
        } for row in node_rows],
        "edges": edges,
    }
