"""Select Recon endpoints that have enough black-box evidence for Attack.

Recon deliberately does not execute state-changing routes merely to prove that
they exist.  A route declared by a public first-party client bundle or a public
API document is nevertheless concrete black-box evidence for the separately
authorized Attack stage.  Generic CRUD inference remains inventory-only.
"""

from __future__ import annotations


ATTACK_ELIGIBLE_ENDPOINT_SQL = """(
    instr(lower(e.normalized_path),'%7b')=0
    AND instr(lower(e.normalized_path),'%7d')=0
    AND instr(e.normalized_path,'{{')=0
    AND instr(e.normalized_path,'}}')=0
    AND (
        COALESCE(e.is_excluded,0)=0
        OR (
            e.verification_status='candidate'
            AND e.exclude_reason='unverified_candidate'
            AND EXISTS (
                SELECT 1 FROM endpoint_observations attack_surface_observation
                WHERE attack_surface_observation.endpoint_id=e.endpoint_id
                  AND (
                      (attack_surface_observation.source_tool='adaptive_js'
                       AND attack_surface_observation.discovery_kind='js_http_call')
                      OR
                      (attack_surface_observation.source_tool='passive_declaration'
                       AND attack_surface_observation.discovery_kind='api_spec_declaration')
                      OR attack_surface_observation.discovery_kind='form_action'
                  )
            )
        )
    )
)"""
