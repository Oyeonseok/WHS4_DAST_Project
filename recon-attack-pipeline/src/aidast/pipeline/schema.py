"""SQLite contracts: shared pipeline v9 and legacy review storage v6."""

from __future__ import annotations

import sqlite3


PIPELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS stage_runs (
    stage_run_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage TEXT NOT NULL CHECK(length(trim(stage)) > 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','running','completed','failed','cancelled','skipped')),
    manifest_path TEXT,
    error_message TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stage_run_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_stage_runs_scan ON stage_runs(scan_id, stage, status);

CREATE TABLE IF NOT EXISTS attack_tasks (
    task_id TEXT PRIMARY KEY NOT NULL,
    stage_run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    skill_name TEXT NOT NULL CHECK(length(trim(skill_name)) > 0),
    endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','running','completed','failed','cancelled','skipped')),
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    error_message TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    UNIQUE(task_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_tasks_run ON attack_tasks(stage_run_id, status);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    vuln_type TEXT NOT NULL CHECK(length(trim(vuln_type)) > 0),
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    description TEXT,
    cvss_score REAL CHECK(cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10),
    cvss_vector TEXT,
    cwe_id TEXT,
    status TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK(status IN ('unreviewed','confirmed','rejected','resolved')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity);

CREATE TABLE IF NOT EXISTS attack_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    task_id TEXT,
    skill_name TEXT NOT NULL CHECK(length(trim(skill_name)) > 0),
    endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    request_fingerprint TEXT NOT NULL CHECK(length(trim(request_fingerprint)) > 0),
    method TEXT,
    url TEXT,
    identity_role TEXT NOT NULL DEFAULT 'unauthenticated',
    payload_variant TEXT NOT NULL DEFAULT '',
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_signature TEXT,
    outcome TEXT,
    finding_id TEXT REFERENCES findings(finding_id),
    resolution_reason TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id),
    UNIQUE(scan_id, skill_name, request_fingerprint, identity_role, payload_variant)
);
CREATE INDEX IF NOT EXISTS idx_attack_attempts_task ON attack_attempts(task_id);

CREATE TABLE IF NOT EXISTS attack_http_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    policy_id TEXT NOT NULL CHECK(length(trim(policy_id)) > 0),
    method TEXT NOT NULL CHECK(length(trim(method)) > 0),
    url TEXT NOT NULL CHECK(length(trim(url)) > 0),
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint) = 64),
    status TEXT NOT NULL CHECK(status IN
        ('reserved','running','completed','failed','outcome_unknown')),
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_bytes INTEGER CHECK(response_bytes IS NULL OR response_bytes >= 0),
    result_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json)),
    authorization_source TEXT CHECK(authorization_source IS NULL OR
        authorization_source IN
        ('scope_safe_method','scope_active_mutation','approved_envelope')),
    authorization_reference_id TEXT,
    endpoint_provenance TEXT CHECK(endpoint_provenance IS NULL OR
        endpoint_provenance IN
        ('network_observed','recon_candidate','agent_proposed')),
    endpoint_reference_id TEXT REFERENCES endpoints(endpoint_id),
    risk_class TEXT CHECK(risk_class IS NULL OR risk_class IN
        ('http_probe','application_mutation','test_resource_create',
         'test_resource_delete','external_side_effect','destructive_or_bulk')),
    error_message TEXT,
    scheduled_at REAL NOT NULL,
    dispatched_at REAL,
    finished_at REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_http_budget
    ON attack_http_requests(scan_id, policy_id, scheduled_at);
CREATE INDEX IF NOT EXISTS idx_attack_http_active
    ON attack_http_requests(stage_run_id, status);

CREATE TABLE IF NOT EXISTS attack_authorization_envelopes (
    envelope_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
    method TEXT NOT NULL CHECK(method IN ('POST','PUT','PATCH','DELETE')),
    origin TEXT NOT NULL,
    normalized_path TEXT NOT NULL,
    provenance_kind TEXT NOT NULL CHECK(provenance_kind IN ('recon_candidate','agent_proposed')),
    evidence_endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    risk_class TEXT NOT NULL CHECK(risk_class IN
        ('application_mutation','test_resource_create','test_resource_delete',
         'external_side_effect')),
    approval_reason TEXT NOT NULL CHECK(approval_reason IN
        ('external_side_effect','high_impact_path','unproven_delete_ownership')),
    max_requests INTEGER NOT NULL CHECK(max_requests BETWEEN 1 AND 10),
    used_requests INTEGER NOT NULL DEFAULT 0 CHECK(used_requests BETWEEN 0 AND max_requests),
    max_body_bytes INTEGER NOT NULL CHECK(max_body_bytes BETWEEN 0 AND 16384),
    status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired')),
    requested_at REAL NOT NULL,
    decided_at REAL,
    expires_at REAL,
    FOREIGN KEY(stage_run_id,scan_id) REFERENCES stage_runs(stage_run_id,scan_id),
    FOREIGN KEY(task_id,scan_id) REFERENCES attack_tasks(task_id,scan_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_authorization_pending
    ON attack_authorization_envelopes(stage_run_id,status,requested_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_authorization_active
    ON attack_authorization_envelopes(
        stage_run_id,task_id,policy_id,method,origin,normalized_path
    ) WHERE status IN ('pending','approved');

CREATE TABLE IF NOT EXISTS attack_facts (
    fact_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    fact_type TEXT NOT NULL CHECK(length(trim(fact_type)) > 0),
    fact_key TEXT NOT NULL CHECK(length(trim(fact_key)) > 0),
    fact_value TEXT,
    confidence REAL NOT NULL DEFAULT 1.0 CHECK(confidence BETWEEN 0 AND 1),
    source_endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    source_finding_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(source_finding_id, scan_id) REFERENCES findings(finding_id, scan_id),
    UNIQUE(scan_id, fact_type, fact_key)
);

CREATE TABLE IF NOT EXISTS attack_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    role TEXT NOT NULL DEFAULT 'unknown',
    method TEXT NOT NULL DEFAULT 'GET',
    url TEXT NOT NULL,
    request_headers TEXT,
    request_body BLOB,
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_headers TEXT,
    response_body BLOB,
    response_time_ms REAL CHECK(response_time_ms IS NULL OR response_time_ms >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attack_requests_finding ON attack_requests(finding_id);

CREATE TABLE IF NOT EXISTS finding_chains (
    chain_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    combined_severity TEXT NOT NULL CHECK(combined_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    description TEXT,
    status TEXT NOT NULL DEFAULT 'proposed'
        CHECK(status IN ('proposed','demonstrated','rejected','resolved')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_finding_chains_scan ON finding_chains(scan_id);

CREATE TABLE IF NOT EXISTS finding_chain_nodes (
    chain_id TEXT NOT NULL REFERENCES finding_chains(chain_id),
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    position INTEGER NOT NULL CHECK(position >= 0),
    role TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(chain_id, finding_id),
    UNIQUE(chain_id, position)
);

CREATE TABLE IF NOT EXISTS chain_candidates (
    candidate_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    chain_id TEXT REFERENCES finding_chains(chain_id),
    status TEXT NOT NULL DEFAULT 'proposed'
        CHECK(status IN ('proposed','testing','evidence_collected','rejected','inconclusive')),
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    hypothesis TEXT NOT NULL CHECK(length(trim(hypothesis)) > 0),
    terminal_impact TEXT,
    confidence REAL NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 1),
    hypothesis_sha256 TEXT NOT NULL CHECK(length(hypothesis_sha256) = 64),
    resolution_reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id),
    FOREIGN KEY(source_finding_id, scan_id) REFERENCES findings(finding_id, scan_id),
    UNIQUE(stage_run_id, source_finding_id, hypothesis_sha256)
);
CREATE INDEX IF NOT EXISTS idx_chain_candidates_run
    ON chain_candidates(stage_run_id, status);

CREATE TABLE IF NOT EXISTS chain_candidate_nodes (
    candidate_id TEXT NOT NULL REFERENCES chain_candidates(candidate_id),
    position INTEGER NOT NULL CHECK(position >= 0),
    finding_id TEXT REFERENCES findings(finding_id),
    expected_vuln_type TEXT NOT NULL CHECK(length(trim(expected_vuln_type)) > 0),
    node_role TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(candidate_id, position)
);

CREATE TABLE IF NOT EXISTS chain_candidate_edges (
    candidate_id TEXT NOT NULL REFERENCES chain_candidates(candidate_id),
    edge_position INTEGER NOT NULL CHECK(edge_position >= 0),
    from_position INTEGER NOT NULL CHECK(from_position >= 0),
    to_position INTEGER NOT NULL CHECK(to_position > from_position),
    relationship TEXT NOT NULL CHECK(length(trim(relationship)) > 0),
    evidence_summary TEXT,
    PRIMARY KEY(candidate_id, edge_position),
    FOREIGN KEY(candidate_id, from_position)
        REFERENCES chain_candidate_nodes(candidate_id, position),
    FOREIGN KEY(candidate_id, to_position)
        REFERENCES chain_candidate_nodes(candidate_id, position)
);

CREATE TABLE IF NOT EXISTS chain_evidence (
    chain_evidence_id TEXT PRIMARY KEY NOT NULL,
    candidate_id TEXT NOT NULL REFERENCES chain_candidates(candidate_id),
    evidence_kind TEXT NOT NULL CHECK(length(trim(evidence_kind)) > 0),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_chain_evidence_candidate
    ON chain_evidence(candidate_id);

CREATE TABLE IF NOT EXISTS chain_executions (
    execution_id TEXT PRIMARY KEY NOT NULL,
    candidate_id TEXT NOT NULL UNIQUE REFERENCES chain_candidates(candidate_id),
    chain_id TEXT UNIQUE REFERENCES finding_chains(chain_id),
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK(status IN ('running','succeeded','rejected','inconclusive','outcome_unknown')),
    reason TEXT,
    terminal_impact TEXT,
    terminal_assertion_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(terminal_assertion_json)),
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id),
    CHECK((status='succeeded' AND chain_id IS NOT NULL)
          OR (status!='succeeded' AND chain_id IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_chain_executions_run
    ON chain_executions(stage_run_id, status);

CREATE TABLE IF NOT EXISTS chain_execution_steps (
    execution_id TEXT NOT NULL REFERENCES chain_executions(execution_id),
    position INTEGER NOT NULL CHECK(position >= 0),
    candidate_node_position INTEGER NOT NULL CHECK(candidate_node_position >= 0),
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    request_id TEXT NOT NULL UNIQUE REFERENCES attack_http_requests(request_id),
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attack_attempts(attempt_id),
    input_binding_hashes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(input_binding_hashes_json)),
    output_capture_hashes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(output_capture_hashes_json)),
    assertion_results_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(assertion_results_json)),
    evidence_summary TEXT NOT NULL CHECK(length(trim(evidence_summary)) > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(execution_id, position),
    UNIQUE(execution_id, candidate_node_position)
);

CREATE TABLE IF NOT EXISTS chain_execution_bindings (
    execution_id TEXT NOT NULL,
    edge_position INTEGER NOT NULL CHECK(edge_position >= 0),
    from_step_position INTEGER NOT NULL CHECK(from_step_position >= 0),
    to_step_position INTEGER NOT NULL CHECK(to_step_position > from_step_position),
    binding_name TEXT NOT NULL CHECK(length(trim(binding_name)) > 0),
    value_sha256 TEXT NOT NULL CHECK(length(value_sha256) = 64),
    source_kind TEXT CHECK(source_kind IS NULL OR source_kind IN ('json_path','response_header')),
    source_path_json TEXT CHECK(source_path_json IS NULL OR json_valid(source_path_json)),
    target_kind TEXT CHECK(target_kind IS NULL OR target_kind IN
        ('path_parameter','query_parameter','request_header','json_body')),
    target_path_json TEXT CHECK(target_path_json IS NULL OR json_valid(target_path_json)),
    PRIMARY KEY(execution_id, edge_position, binding_name),
    FOREIGN KEY(execution_id, from_step_position)
        REFERENCES chain_execution_steps(execution_id, position),
    FOREIGN KEY(execution_id, to_step_position)
        REFERENCES chain_execution_steps(execution_id, position)
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_event_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT,
    task_id TEXT,
    event_type TEXT NOT NULL CHECK(length(trim(event_type)) > 0),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_audit_events_scan ON audit_events(scan_id, created_at);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;

CREATE TABLE IF NOT EXISTS credential_references (
    credential_reference_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    session_id TEXT REFERENCES sessions(session_id),
    label TEXT NOT NULL CHECK(length(trim(label)) > 0),
    reference_uri TEXT NOT NULL CHECK(
        reference_uri GLOB 'env://?*' OR reference_uri GLOB 'keyring://?*'
        OR reference_uri GLOB 'vault://?*'),
    identity_role TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, label)
);

CREATE TABLE IF NOT EXISTS validation_cases (
    case_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    target_kind TEXT NOT NULL CHECK(target_kind IN ('finding','chain')),
    finding_id TEXT REFERENCES findings(finding_id),
    chain_id TEXT REFERENCES finding_chains(chain_id),
    latest_stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    decision_stage_run_id TEXT REFERENCES stage_runs(stage_run_id),
    processing_phase TEXT NOT NULL CHECK(processing_phase IN
        ('queued','blind_replay','developing','unblinding','completed','interrupted')),
    current_status TEXT CHECK(current_status IN
        ('CONFIRMED','DISPROVEN','OUT_OF_SCOPE','KNOWN','UNDERPOWERED','BLOCKED','INCONCLUSIVE','CONTESTED')),
    state_version INTEGER NOT NULL DEFAULT 0 CHECK(state_version >= 0),
    attack_skill_name TEXT,
    skill_sha256 TEXT CHECK(skill_sha256 IS NULL OR length(skill_sha256)=64),
    validation_profile_sha256 TEXT CHECK(validation_profile_sha256 IS NULL OR length(validation_profile_sha256)=64),
    source_policy_sha256 TEXT CHECK(source_policy_sha256 IS NULL OR length(source_policy_sha256)=64),
    current_policy_sha256 TEXT CHECK(current_policy_sha256 IS NULL OR length(current_policy_sha256)=64),
    blind_case_sha256 TEXT CHECK(blind_case_sha256 IS NULL OR length(blind_case_sha256)=64),
    blind_assessment_sha256 TEXT CHECK(blind_assessment_sha256 IS NULL OR length(blind_assessment_sha256)=64),
    attack_claim_sha256 TEXT CHECK(attack_claim_sha256 IS NULL OR length(attack_claim_sha256)=64),
    known_source_case_id TEXT REFERENCES validation_cases(case_id),
    impact_boundary INTEGER CHECK(impact_boundary IS NULL OR impact_boundary BETWEEN 0 AND 3),
    impact_sensitivity INTEGER CHECK(impact_sensitivity IS NULL OR impact_sensitivity BETWEEN 0 AND 3),
    impact_actor_requirements INTEGER CHECK(impact_actor_requirements IS NULL OR impact_actor_requirements BETWEEN 0 AND 3),
    impact_score INTEGER CHECK(impact_score IS NULL OR impact_score BETWEEN 0 AND 9),
    severity TEXT CHECK(severity IS NULL OR severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    decision_json TEXT CHECK(decision_json IS NULL OR json_valid(decision_json)),
    decision_sha256 TEXT CHECK(decision_sha256 IS NULL OR length(decision_sha256)=64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((target_kind='finding' AND finding_id IS NOT NULL AND chain_id IS NULL)
       OR (target_kind='chain' AND chain_id IS NOT NULL AND finding_id IS NULL)),
    CHECK((current_status IS NULL AND decision_json IS NULL AND decision_sha256 IS NULL)
       OR (current_status IS NOT NULL AND decision_json IS NOT NULL AND decision_sha256 IS NOT NULL)),
    CHECK(current_status!='KNOWN' OR known_source_case_id IS NOT NULL),
    CHECK(impact_score IS NULL OR impact_score = impact_boundary + impact_sensitivity + impact_actor_requirements),
    UNIQUE(case_id, scan_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_case_finding
    ON validation_cases(scan_id, finding_id) WHERE finding_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_case_chain
    ON validation_cases(scan_id, chain_id) WHERE chain_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_validation_cases_stage ON validation_cases(latest_stage_run_id, processing_phase);

CREATE TABLE IF NOT EXISTS validation_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    batch_no INTEGER NOT NULL CHECK(batch_no >= 1),
    attempt_kind TEXT NOT NULL CHECK(attempt_kind IN ('target','positive_control','negative_control')),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
    signal_type TEXT NOT NULL CHECK(signal_type IN
        ('oob_callback','response_diff','error_signature','timing','dom_effect','state_change','authorization_boundary')),
    outcome TEXT NOT NULL CHECK(outcome IN ('observed','not_observed','blocked','error','outcome_unknown')),
    signal_observed INTEGER CHECK(signal_observed IS NULL OR signal_observed IN (0,1)),
    blocker_axis TEXT CHECK(blocker_axis IS NULL OR blocker_axis IN
        ('identity_auth','state_setup','encoding_transport','timing_concurrency','environment_topology')),
    observation_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(observation_json)),
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    UNIQUE(case_id, stage_run_id, batch_no, attempt_kind, ordinal)
);

CREATE TABLE IF NOT EXISTS validation_development_actions (
    action_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 2),
    blocker_axis TEXT NOT NULL CHECK(blocker_axis IN
        ('identity_auth','state_setup','encoding_transport','timing_concurrency')),
    action_type TEXT NOT NULL CHECK(length(trim(action_type)) > 0),
    status TEXT NOT NULL CHECK(status IN ('planned','running','succeeded','failed','outcome_unknown')),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(case_id, stage_run_id, ordinal)
);

CREATE TABLE IF NOT EXISTS validation_evidence (
    evidence_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    attempt_id TEXT REFERENCES validation_attempts(attempt_id),
    development_action_id TEXT REFERENCES validation_development_actions(action_id),
    evidence_kind TEXT NOT NULL CHECK(length(trim(evidence_kind)) > 0),
    details_json TEXT NOT NULL CHECK(json_valid(details_json) AND length(CAST(details_json AS BLOB)) <= 8192),
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
    content_length INTEGER NOT NULL CHECK(content_length >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((attempt_id IS NULL AND development_action_id IS NULL)
       OR (attempt_id IS NOT NULL AND development_action_id IS NULL)
       OR (attempt_id IS NULL AND development_action_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS validation_impact_hypotheses (
    hypothesis_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 3),
    gap_axis TEXT NOT NULL CHECK(gap_axis IN ('boundary','sensitivity','actor_requirements')),
    path_id TEXT NOT NULL CHECK(length(trim(path_id)) > 0),
    hypothesis_kind TEXT NOT NULL CHECK(length(trim(hypothesis_kind)) > 0),
    current_score INTEGER NOT NULL CHECK(current_score BETWEEN 0 AND 3),
    reason_json TEXT NOT NULL CHECK(json_valid(reason_json)),
    required_preconditions_json TEXT NOT NULL CHECK(json_valid(required_preconditions_json)),
    recommended_actions_json TEXT NOT NULL CHECK(json_valid(recommended_actions_json)),
    expected_signal_json TEXT NOT NULL CHECK(json_valid(expected_signal_json)),
    supporting_evidence_ids_json TEXT NOT NULL CHECK(json_valid(supporting_evidence_ids_json)),
    execution_owner TEXT NOT NULL CHECK(execution_owner IN ('validation','chaining','manual')),
    feasibility TEXT NOT NULL CHECK(feasibility IN ('low','medium','high')),
    potential_impact_json TEXT NOT NULL CHECK(json_valid(potential_impact_json)),
    skill_sha256 TEXT NOT NULL CHECK(length(skill_sha256)=64),
    validation_profile_sha256 TEXT NOT NULL CHECK(length(validation_profile_sha256)=64),
    proposal_sha256 TEXT NOT NULL CHECK(length(proposal_sha256)=64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(case_id, stage_run_id, ordinal),
    UNIQUE(case_id, stage_run_id, path_id)
);

CREATE TABLE IF NOT EXISTS validation_http_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    attempt_id TEXT REFERENCES validation_attempts(attempt_id),
    development_action_id TEXT REFERENCES validation_development_actions(action_id),
    policy_id TEXT NOT NULL CHECK(length(trim(policy_id)) > 0),
    policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
    method TEXT NOT NULL CHECK(length(trim(method)) > 0),
    url TEXT NOT NULL CHECK(length(trim(url)) > 0),
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint)=64),
    status TEXT NOT NULL CHECK(status IN ('reserved','running','completed','failed','outcome_unknown')),
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_bytes INTEGER CHECK(response_bytes IS NULL OR response_bytes >= 0),
    result_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json)),
    error_message TEXT,
    scheduled_at REAL NOT NULL,
    dispatched_at REAL,
    finished_at REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((attempt_id IS NOT NULL AND development_action_id IS NULL)
       OR (attempt_id IS NULL AND development_action_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_validation_http_budget ON validation_http_requests(scan_id, policy_id, scheduled_at);
CREATE INDEX IF NOT EXISTS idx_validation_http_active ON validation_http_requests(stage_run_id, status);

CREATE TABLE IF NOT EXISTS finding_reproduction_specs (
    finding_id TEXT PRIMARY KEY NOT NULL REFERENCES findings(finding_id),
    attack_skill_name TEXT NOT NULL CHECK(length(trim(attack_skill_name)) > 0),
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    method TEXT NOT NULL CHECK(length(trim(method)) > 0),
    endpoint_template TEXT NOT NULL CHECK(length(trim(endpoint_template)) > 0),
    injection_location TEXT NOT NULL CHECK(injection_location IN ('path','query','header','cookie','body')),
    parameter_name TEXT NOT NULL CHECK(length(trim(parameter_name)) > 0),
    payload_template_json TEXT NOT NULL CHECK(json_valid(payload_template_json)),
    required_identity_roles_json TEXT NOT NULL CHECK(json_valid(required_identity_roles_json)),
    source_attempt_ids_json TEXT NOT NULL CHECK(json_valid(source_attempt_ids_json)),
    source_request_ids_json TEXT NOT NULL CHECK(json_valid(source_request_ids_json)),
    payload_structure_sha256 TEXT NOT NULL CHECK(length(payload_structure_sha256)=64),
    source_policy_sha256 TEXT NOT NULL CHECK(length(source_policy_sha256)=64),
    runtime_contract_json TEXT CHECK(runtime_contract_json IS NULL OR json_valid(runtime_contract_json)),
    runtime_contract_sha256 TEXT CHECK(runtime_contract_sha256 IS NULL OR length(runtime_contract_sha256)=64),
    development_contract_json TEXT CHECK(
        development_contract_json IS NULL OR json_valid(development_contract_json)),
    development_contract_sha256 TEXT CHECK(
        development_contract_sha256 IS NULL OR length(development_contract_sha256)=64),
    spec_sha256 TEXT NOT NULL CHECK(length(spec_sha256)=64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((runtime_contract_json IS NULL) = (runtime_contract_sha256 IS NULL)),
    CHECK((development_contract_json IS NULL) = (development_contract_sha256 IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_validation_stage
    ON stage_runs(scan_id) WHERE stage='validation' AND status IN ('pending','running');

CREATE TRIGGER IF NOT EXISTS validation_evidence_no_update BEFORE UPDATE ON validation_evidence
BEGIN SELECT RAISE(ABORT, 'validation evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS validation_evidence_no_delete BEFORE DELETE ON validation_evidence
BEGIN SELECT RAISE(ABORT, 'validation evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS validation_attempts_completed_no_update BEFORE UPDATE ON validation_attempts
WHEN OLD.finished_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'completed validation attempts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS validation_attempts_completed_no_delete BEFORE DELETE ON validation_attempts
WHEN OLD.finished_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'completed validation attempts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS finding_reproduction_specs_no_update
BEFORE UPDATE ON finding_reproduction_specs
BEGIN SELECT RAISE(ABORT, 'finding reproduction specs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS finding_reproduction_specs_no_delete
BEFORE DELETE ON finding_reproduction_specs
BEGIN SELECT RAISE(ABORT, 'finding reproduction specs are immutable'); END;

CREATE TRIGGER IF NOT EXISTS finding_chain_nodes_scan_insert
BEFORE INSERT ON finding_chain_nodes
WHEN (SELECT scan_id FROM findings WHERE finding_id=NEW.finding_id)
     != (SELECT scan_id FROM finding_chains WHERE chain_id=NEW.chain_id)
BEGIN SELECT RAISE(ABORT, 'finding relationship crosses scans'); END;
CREATE TRIGGER IF NOT EXISTS finding_chain_nodes_scan_update
BEFORE UPDATE ON finding_chain_nodes
WHEN (SELECT scan_id FROM findings WHERE finding_id=NEW.finding_id)
     != (SELECT scan_id FROM finding_chains WHERE chain_id=NEW.chain_id)
BEGIN SELECT RAISE(ABORT, 'finding relationship crosses scans'); END;
"""


VALIDATION_CASES_WITHOUT_SIMILARITY_SCHEMA = """
CREATE TABLE validation_cases_without_similarity (
    case_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    target_kind TEXT NOT NULL CHECK(target_kind IN ('finding','chain')),
    finding_id TEXT REFERENCES findings(finding_id),
    chain_id TEXT REFERENCES finding_chains(chain_id),
    latest_stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    decision_stage_run_id TEXT REFERENCES stage_runs(stage_run_id),
    processing_phase TEXT NOT NULL CHECK(processing_phase IN
        ('queued','blind_replay','developing','unblinding','completed','interrupted')),
    current_status TEXT CHECK(current_status IN
        ('CONFIRMED','DISPROVEN','OUT_OF_SCOPE','KNOWN','UNDERPOWERED','BLOCKED','INCONCLUSIVE','CONTESTED')),
    state_version INTEGER NOT NULL DEFAULT 0 CHECK(state_version >= 0),
    attack_skill_name TEXT,
    skill_sha256 TEXT CHECK(skill_sha256 IS NULL OR length(skill_sha256)=64),
    validation_profile_sha256 TEXT CHECK(validation_profile_sha256 IS NULL OR length(validation_profile_sha256)=64),
    source_policy_sha256 TEXT CHECK(source_policy_sha256 IS NULL OR length(source_policy_sha256)=64),
    current_policy_sha256 TEXT CHECK(current_policy_sha256 IS NULL OR length(current_policy_sha256)=64),
    blind_case_sha256 TEXT CHECK(blind_case_sha256 IS NULL OR length(blind_case_sha256)=64),
    blind_assessment_sha256 TEXT CHECK(blind_assessment_sha256 IS NULL OR length(blind_assessment_sha256)=64),
    attack_claim_sha256 TEXT CHECK(attack_claim_sha256 IS NULL OR length(attack_claim_sha256)=64),
    known_source_case_id TEXT REFERENCES validation_cases_without_similarity(case_id),
    impact_boundary INTEGER CHECK(impact_boundary IS NULL OR impact_boundary BETWEEN 0 AND 3),
    impact_sensitivity INTEGER CHECK(impact_sensitivity IS NULL OR impact_sensitivity BETWEEN 0 AND 3),
    impact_actor_requirements INTEGER CHECK(impact_actor_requirements IS NULL OR impact_actor_requirements BETWEEN 0 AND 3),
    impact_score INTEGER CHECK(impact_score IS NULL OR impact_score BETWEEN 0 AND 9),
    severity TEXT CHECK(severity IS NULL OR severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    decision_json TEXT CHECK(decision_json IS NULL OR json_valid(decision_json)),
    decision_sha256 TEXT CHECK(decision_sha256 IS NULL OR length(decision_sha256)=64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((target_kind='finding' AND finding_id IS NOT NULL AND chain_id IS NULL)
       OR (target_kind='chain' AND chain_id IS NOT NULL AND finding_id IS NULL)),
    CHECK((current_status IS NULL AND decision_json IS NULL AND decision_sha256 IS NULL)
       OR (current_status IS NOT NULL AND decision_json IS NOT NULL AND decision_sha256 IS NOT NULL)),
    CHECK(current_status!='KNOWN' OR known_source_case_id IS NOT NULL),
    CHECK(impact_score IS NULL OR impact_score = impact_boundary + impact_sensitivity + impact_actor_requirements),
    UNIQUE(case_id, scan_id)
);
"""


def _remove_known_similarity_column(conn: sqlite3.Connection) -> None:
    columns = [row[1] for row in conn.execute("PRAGMA table_info(validation_cases)")]
    if "known_similarity" not in columns:
        return
    retained = [name for name in columns if name != "known_similarity"]
    names = ",".join(retained)
    foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    conn.commit()
    if foreign_keys:
        conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.executescript(
            "BEGIN IMMEDIATE;\n"
            + VALIDATION_CASES_WITHOUT_SIMILARITY_SCHEMA
            + f"INSERT INTO validation_cases_without_similarity ({names}) SELECT {names} FROM validation_cases;\n"
            + "DROP TABLE validation_cases;\n"
            + "ALTER TABLE validation_cases_without_similarity RENAME TO validation_cases;\n"
            + "COMMIT;"
        )
        conn.executescript("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_case_finding
                ON validation_cases(scan_id, finding_id) WHERE finding_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_case_chain
                ON validation_cases(scan_id, chain_id) WHERE chain_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_validation_cases_stage
                ON validation_cases(latest_stage_run_id, processing_phase);
        """)
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        if foreign_keys:
            conn.execute("PRAGMA foreign_keys=ON")
    if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise sqlite3.IntegrityError("validation_cases migration broke foreign keys")


def migrate_pipeline_schema(conn: sqlite3.Connection) -> None:
    """Create shared pipeline tables without rebuilding existing data."""
    # executescript commits an existing transaction; caller owns initialization.
    conn.executescript(PIPELINE_SCHEMA)
    _remove_known_similarity_column(conn)
    attempt_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(attack_attempts)")
    }
    for name, declaration in (
        ("finding_id", "TEXT REFERENCES findings(finding_id)"),
        ("resolution_reason", "TEXT"),
        ("resolved_at", "TEXT"),
    ):
        if name not in attempt_columns:
            conn.execute(f"ALTER TABLE attack_attempts ADD COLUMN {name} {declaration}")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_attempts_finding "
        "ON attack_attempts(finding_id)"
    )
    request_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(attack_http_requests)")
    }
    if "result_json" not in request_columns:
        conn.execute(
            "ALTER TABLE attack_http_requests ADD COLUMN result_json "
            "TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json))"
        )
    if "policy_sha256" not in request_columns:
        conn.execute("ALTER TABLE attack_http_requests ADD COLUMN policy_sha256 TEXT")
    if "authorization_source" not in request_columns:
        conn.execute(
            "ALTER TABLE attack_http_requests ADD COLUMN authorization_source TEXT "
            "CHECK(authorization_source IS NULL OR authorization_source IN "
            "('scope_safe_method','scope_active_mutation','approved_envelope'))"
        )
    if "authorization_reference_id" not in request_columns:
        conn.execute(
            "ALTER TABLE attack_http_requests ADD COLUMN authorization_reference_id TEXT"
        )
    if "endpoint_provenance" not in request_columns:
        conn.execute(
            "ALTER TABLE attack_http_requests ADD COLUMN endpoint_provenance TEXT "
            "CHECK(endpoint_provenance IS NULL OR endpoint_provenance IN "
            "('network_observed','recon_candidate','agent_proposed'))"
        )
    if "endpoint_reference_id" not in request_columns:
        conn.execute(
            "ALTER TABLE attack_http_requests ADD COLUMN endpoint_reference_id TEXT "
            "REFERENCES endpoints(endpoint_id)"
        )
    if "risk_class" not in request_columns:
        conn.execute(
            "ALTER TABLE attack_http_requests ADD COLUMN risk_class TEXT "
            "CHECK(risk_class IS NULL OR risk_class IN "
            "('http_probe','application_mutation','test_resource_create',"
            "'test_resource_delete','external_side_effect','destructive_or_bulk'))"
        )
    envelope_columns = {
        row[1] for row in conn.execute(
            "PRAGMA table_info(attack_authorization_envelopes)"
        )
    }
    if "risk_class" not in envelope_columns:
        conn.execute(
            "ALTER TABLE attack_authorization_envelopes ADD COLUMN risk_class "
            "TEXT NOT NULL DEFAULT 'application_mutation'"
        )
    if "approval_reason" not in envelope_columns:
        conn.execute(
            "ALTER TABLE attack_authorization_envelopes ADD COLUMN approval_reason "
            "TEXT NOT NULL DEFAULT 'high_impact_path'"
        )
    reproduction_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(finding_reproduction_specs)")
    }
    if "runtime_contract_json" not in reproduction_columns:
        conn.execute(
            "ALTER TABLE finding_reproduction_specs ADD COLUMN runtime_contract_json "
            "TEXT CHECK(runtime_contract_json IS NULL OR json_valid(runtime_contract_json))"
        )
    if "runtime_contract_sha256" not in reproduction_columns:
        conn.execute(
            "ALTER TABLE finding_reproduction_specs ADD COLUMN runtime_contract_sha256 "
            "TEXT CHECK(runtime_contract_sha256 IS NULL OR length(runtime_contract_sha256)=64)"
        )
    if "development_contract_json" not in reproduction_columns:
        conn.execute(
            "ALTER TABLE finding_reproduction_specs ADD COLUMN development_contract_json "
            "TEXT CHECK(development_contract_json IS NULL OR json_valid(development_contract_json))"
        )
    if "development_contract_sha256" not in reproduction_columns:
        conn.execute(
            "ALTER TABLE finding_reproduction_specs ADD COLUMN development_contract_sha256 "
            "TEXT CHECK(development_contract_sha256 IS NULL OR "
            "length(development_contract_sha256)=64)"
        )
    binding_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(chain_execution_bindings)")
    }
    for name, declaration in (
        ("source_kind", "TEXT CHECK(source_kind IS NULL OR source_kind IN ('json_path','response_header'))"),
        ("source_path_json", "TEXT CHECK(source_path_json IS NULL OR json_valid(source_path_json))"),
        ("target_kind", "TEXT CHECK(target_kind IS NULL OR target_kind IN ('path_parameter','query_parameter','request_header','json_body'))"),
        ("target_path_json", "TEXT CHECK(target_path_json IS NULL OR json_valid(target_path_json))"),
    ):
        if name not in binding_columns:
            conn.execute(f"ALTER TABLE chain_execution_bindings ADD COLUMN {name} {declaration}")
    for table, column, relation in (
        ("attack_tasks", "endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("attack_attempts", "endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("attack_facts", "source_endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("findings", "endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("credential_references", "session_id", "sessions e JOIN origins o ON o.origin_id=e.origin_id"),
    ):
        relation_id = "session_id" if column == "session_id" else "endpoint_id"
        for action in ("INSERT", "UPDATE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_scan_{action.lower()}
                BEFORE {action} ON {table}
                WHEN NEW.{column} IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM {relation} JOIN assets a ON a.asset_id=o.asset_id
                    WHERE e.{relation_id}=NEW.{column} AND a.scan_id=NEW.scan_id)
                BEGIN SELECT RAISE(ABORT, 'reference does not belong to scan'); END""")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version < 9:
        conn.execute("PRAGMA user_version=9")


ATTACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_runs (
    run_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL,
    source_manifest_id TEXT NOT NULL,
    source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
    source_database_sha256 TEXT NOT NULL CHECK(length(source_database_sha256)=64),
    source_manifest_path TEXT NOT NULL,
    source_database_path TEXT NOT NULL,
    scope_digest TEXT NOT NULL DEFAULT '',
    policy_digest TEXT NOT NULL DEFAULT '',
    catalog_digest TEXT NOT NULL DEFAULT '',
    plan_revision INTEGER NOT NULL DEFAULT 0 CHECK(plan_revision>=0),
    authorization_id TEXT,
    status TEXT NOT NULL DEFAULT 'created' CHECK(status IN
        ('created','verifying_handoff','planning','awaiting_approval','ready','running',
         'completed','blocked','paused','failed','cancelled')),
    cursor_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(cursor_json)),
    revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK(revocation_generation>=0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS attack_plans (
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>0),
    plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64),
    document_json TEXT NOT NULL CHECK(json_valid(document_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(run_id,revision),
    UNIQUE(run_id,scan_id,revision),
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS attack_plan_tasks (
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    endpoint_id TEXT,
    catalog_id TEXT NOT NULL DEFAULT '',
    task_digest TEXT NOT NULL CHECK(length(task_digest)=64),
    document_json TEXT NOT NULL CHECK(json_valid(document_json)),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN
        ('pending','blocked_missing_prerequisite','running','completed','failed',
         'cancelled','skipped','inconclusive','outcome_unknown')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(run_id,plan_revision,task_id),
    UNIQUE(run_id,scan_id,plan_revision,task_id),
    FOREIGN KEY(run_id,scan_id,plan_revision) REFERENCES attack_plans(run_id,scan_id,revision)
);
CREATE TABLE IF NOT EXISTS run_authorizations (
    authorization_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    plan_digest TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    catalog_digest TEXT NOT NULL,
    issuer TEXT NOT NULL,
    approver TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK(revocation_generation>=0),
    revoked_at TEXT,
    document_json TEXT NOT NULL CHECK(json_valid(document_json)),
    UNIQUE(authorization_id,run_id,scan_id),
    FOREIGN KEY(run_id,scan_id,plan_revision) REFERENCES attack_plans(run_id,scan_id,revision)
);
CREATE TABLE IF NOT EXISTS worker_leases (
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    lease_key TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
    expires_at REAL NOT NULL,
    PRIMARY KEY(run_id,lease_key),
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS broker_reservations (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
    reserved_requests INTEGER NOT NULL DEFAULT 1 CHECK(reserved_requests>=0),
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0),
    status TEXT NOT NULL DEFAULT 'reserved' CHECK(status IN
        ('reserved','recorded','cancelled','outcome_unknown')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(reservation_id,run_id,scan_id),
    FOREIGN KEY(run_id,scan_id,plan_revision,task_id)
        REFERENCES attack_plan_tasks(run_id,scan_id,plan_revision,task_id),
    FOREIGN KEY(authorization_id,run_id,scan_id)
        REFERENCES run_authorizations(authorization_id,run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS broker_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    reservation_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    transmission_state TEXT NOT NULL CHECK(transmission_state IN
        ('not_sent','sent','outcome_unknown')),
    redirect_count INTEGER NOT NULL DEFAULT 0 CHECK(redirect_count>=0),
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    bytes_sent INTEGER NOT NULL DEFAULT 0 CHECK(bytes_sent>=0),
    bytes_received INTEGER NOT NULL DEFAULT 0 CHECK(bytes_received>=0),
    elapsed_ms REAL NOT NULL DEFAULT 0 CHECK(elapsed_ms>=0),
    summary_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(summary_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(reservation_id,run_id,scan_id)
        REFERENCES broker_reservations(reservation_id,run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS model_iterations (
    iteration_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    context_hash TEXT NOT NULL CHECK(length(context_hash)=64),
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    catalog_version TEXT NOT NULL,
    raw_result_json TEXT NOT NULL CHECK(json_valid(raw_result_json)),
    validation_json TEXT NOT NULL CHECK(json_valid(validation_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS attack_evidence (
    evidence_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER,
    task_id TEXT,
    attempt_id TEXT REFERENCES attack_attempts(attempt_id),
    kind TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK(length(body_sha256)=64),
    body_length INTEGER NOT NULL CHECK(body_length>=0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((task_id IS NULL)=(plan_revision IS NULL)),
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id),
    FOREIGN KEY(run_id,scan_id,plan_revision,task_id)
        REFERENCES attack_plan_tasks(run_id,scan_id,plan_revision,task_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_evidence_run ON attack_evidence(run_id,created_at);
CREATE INDEX IF NOT EXISTS idx_model_iterations_run ON model_iterations(run_id,created_at);
"""


def migrate_attack_schema(conn: sqlite3.Connection) -> None:
    """Initialize an empty Attack-only v6 database, or reapply its schema.

    Legacy copied databases are deliberately not converted in place. External
    Recon identifiers are checked by the storage API, not cross-database FKs.
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM main.sqlite_master WHERE type='table'")}
    if version not in (0, 6) or tables.intersection({"scans", "assets", "origins", "endpoints"}):
        raise ValueError("expected an empty or thin v6 Attack database; legacy copied databases require a new output directory")
    # These are the shared Attack-owned records, not Recon inventory tables.
    # Keep their local relationships and checks while removing external FKs.
    base_schema = PIPELINE_SCHEMA
    for reference in (" REFERENCES scans(scan_id)", " REFERENCES endpoints(endpoint_id)",
                      " REFERENCES sessions(session_id)"):
        base_schema = base_schema.replace(reference, "")
    conn.executescript(base_schema)
    conn.executescript(ATTACK_SCHEMA)
    additions = {
        "attack_attempts": {
            "run_id": "TEXT REFERENCES attack_runs(run_id)",
            "plan_task_id": "TEXT", "plan_revision": "INTEGER",
            "logical_check_id": "TEXT", "execution_id": "TEXT",
        },
        "attack_facts": {
            "run_id": "TEXT REFERENCES attack_runs(run_id)",
            "source_attempt_id": "TEXT REFERENCES attack_attempts(attempt_id)",
            "expires_at": "TEXT", "superseded_by_fact_id": "TEXT REFERENCES attack_facts(fact_id)",
        },
        "findings": {
            "run_id": "TEXT REFERENCES attack_runs(run_id)",
            "plan_task_id": "TEXT", "plan_revision": "INTEGER", "reviewer_id": "TEXT",
            "hypothesis_id": "TEXT",
        },
    }
    for table, columns in additions.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, declaration in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        for action in ("INSERT", "UPDATE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_run_{action.lower()}
                BEFORE {action} ON {table}
                WHEN NEW.run_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM attack_runs r WHERE r.run_id=NEW.run_id AND r.scan_id=NEW.scan_id)
                BEGIN SELECT RAISE(ABORT, 'reference does not belong to run'); END""")
    for action in ("INSERT", "UPDATE"):
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS attack_evidence_attempt_{action.lower()}
            BEFORE {action} ON attack_evidence WHEN NEW.attempt_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM attack_attempts a WHERE a.attempt_id=NEW.attempt_id
                AND a.scan_id=NEW.scan_id AND a.run_id=NEW.run_id)
            BEGIN SELECT RAISE(ABORT, 'attempt does not belong to run'); END""")
        for table in ("attack_attempts", "findings"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_plan_task_{action.lower()}
                BEFORE {action} ON {table} WHEN
                (NEW.plan_task_id IS NULL)!=(NEW.plan_revision IS NULL) OR
                (NEW.plan_task_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM attack_plan_tasks t WHERE t.run_id=NEW.run_id
                    AND t.scan_id=NEW.scan_id AND t.plan_revision=NEW.plan_revision
                    AND t.task_id=NEW.plan_task_id))
                BEGIN SELECT RAISE(ABORT, 'task does not belong to run'); END""")
        for column, target, identifier in (
            ("source_attempt_id", "attack_attempts", "attempt_id"),
            ("superseded_by_fact_id", "attack_facts", "fact_id"),
        ):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS attack_facts_{column}_{action.lower()}
                BEFORE {action} ON attack_facts WHEN NEW.{column} IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM {target} t WHERE t.{identifier}=NEW.{column}
                    AND t.scan_id=NEW.scan_id AND t.run_id IS NEW.run_id)
                BEGIN SELECT RAISE(ABORT, 'fact source does not belong to run'); END""")
    for table in ("attack_plans", "model_iterations", "attack_evidence", "broker_receipts"):
        for action in ("UPDATE", "DELETE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_immutable_{action.lower()}
                BEFORE {action} ON {table}
                BEGIN SELECT RAISE(ABORT, 'review records are immutable'); END""")
    conn.executescript("""
        CREATE TRIGGER IF NOT EXISTS run_authorizations_immutable_update
        BEFORE UPDATE OF authorization_id,run_id,scan_id,plan_revision,plan_digest,scope_digest,
            policy_digest,catalog_digest,issuer,approver,issued_at,not_before,expires_at,
            revocation_generation,document_json ON run_authorizations
        BEGIN SELECT RAISE(ABORT, 'authorization bindings are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS run_authorizations_immutable_delete
        BEFORE DELETE ON run_authorizations
        BEGIN SELECT RAISE(ABORT, 'authorization bindings are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS run_authorizations_revocation_monotonic
        BEFORE UPDATE OF revoked_at ON run_authorizations
        WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
        BEGIN SELECT RAISE(ABORT, 'authorization revocation is permanent'); END;
        CREATE TRIGGER IF NOT EXISTS attack_runs_generation_monotonic
        BEFORE UPDATE OF revocation_generation ON attack_runs
        WHEN NEW.revocation_generation<OLD.revocation_generation
        BEGIN SELECT RAISE(ABORT, 'revocation generation cannot decrease'); END;
        CREATE TRIGGER IF NOT EXISTS attack_plan_tasks_immutable_update
        BEFORE UPDATE OF task_id,run_id,scan_id,plan_revision,endpoint_id,catalog_id,task_digest,document_json
        ON attack_plan_tasks BEGIN SELECT RAISE(ABORT, 'plan tasks are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_plan_tasks_immutable_delete
        BEFORE DELETE ON attack_plan_tasks BEGIN SELECT RAISE(ABORT, 'plan tasks are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_runs_provenance_immutable
        BEFORE UPDATE OF run_id,scan_id,source_manifest_id,source_manifest_sha256,
            source_database_sha256,source_manifest_path,source_database_path,scope_digest,policy_digest,catalog_digest
        ON attack_runs BEGIN SELECT RAISE(ABORT, 'run provenance is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_demonstrated_update BEFORE UPDATE ON finding_chains
        WHEN NEW.status='demonstrated' AND (NOT EXISTS (
            SELECT 1 FROM finding_chain_nodes n WHERE n.chain_id=NEW.chain_id) OR EXISTS (
            SELECT 1 FROM finding_chain_nodes n JOIN findings f ON f.finding_id=n.finding_id
            WHERE n.chain_id=NEW.chain_id AND f.status!='confirmed'))
        BEGIN SELECT RAISE(ABORT, 'demonstrated chains require confirmed findings'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_demonstrated_insert BEFORE INSERT ON finding_chains
        WHEN NEW.status='demonstrated'
        BEGIN SELECT RAISE(ABORT, 'create proposed chain before demonstrating'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_nodes_confirmed_insert BEFORE INSERT ON finding_chain_nodes
        WHEN (SELECT status FROM finding_chains WHERE chain_id=NEW.chain_id)='demonstrated'
            AND (SELECT status FROM findings WHERE finding_id=NEW.finding_id)!='confirmed'
        BEGIN SELECT RAISE(ABORT, 'demonstrated chains require confirmed findings'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_nodes_confirmed_update BEFORE UPDATE ON finding_chain_nodes
        WHEN (SELECT status FROM finding_chains WHERE chain_id=NEW.chain_id)='demonstrated'
            OR (SELECT status FROM finding_chains WHERE chain_id=OLD.chain_id)='demonstrated'
        BEGIN SELECT RAISE(ABORT, 'demonstrated chain membership is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_nodes_confirmed_delete BEFORE DELETE ON finding_chain_nodes
        WHEN (SELECT status FROM finding_chains WHERE chain_id=OLD.chain_id)='demonstrated'
        BEGIN SELECT RAISE(ABORT, 'demonstrated chain membership is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_finding_confirmation BEFORE UPDATE OF status ON findings
        WHEN NEW.status!='confirmed' AND EXISTS (SELECT 1 FROM finding_chain_nodes n
            JOIN finding_chains c ON c.chain_id=n.chain_id
            WHERE n.finding_id=NEW.finding_id AND c.status='demonstrated')
        BEGIN SELECT RAISE(ABORT, 'reclassify demonstrated chains before their findings'); END;
    """)
    conn.execute("PRAGMA user_version=6")
