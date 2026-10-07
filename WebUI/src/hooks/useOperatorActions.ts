import { useCallback, useEffect, useState } from 'react';
import { apiErrorMessage } from '../lib/transport';

export type OperatorAction = {
  action_id: string;
  action_kind: string;
  status: 'pending' | 'acknowledged' | 'completed' | 'expired' | 'cancelled';
  title: string;
  instruction: string;
  coverage_id: string;
  kind: string;
  state: string;
  vuln_class: string;
  method: string;
  normalized_path: string;
};

function parseActions(value: unknown): OperatorAction[] {
  if (!value || typeof value !== 'object') return [];
  const rows = (value as { actions?: unknown }).actions;
  if (!Array.isArray(rows)) return [];
  return rows.filter((row): row is OperatorAction => {
    if (!row || typeof row !== 'object') return false;
    const item = row as Record<string, unknown>;
    return typeof item.action_id === 'string' && typeof item.status === 'string'
      && typeof item.title === 'string' && typeof item.instruction === 'string';
  });
}

export function useOperatorActions(scanId: string, enabled: boolean, scanStatus: string) {
  const [actions, setActions] = useState<OperatorAction[]>([]);
  const [busy, setBusy] = useState<string>('');
  const [error, setError] = useState('');
  const base = import.meta.env.VITE_API_BASE_URL || location.origin;

  const load = useCallback(async (signal?: AbortSignal) => {
    if (!enabled || !scanId) return;
    const response = await fetch(
      new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/operator-actions`, base),
      { credentials: 'same-origin', cache: 'no-store', signal },
    );
    const body = await response.json();
    if (!response.ok) throw new Error(apiErrorMessage(body.detail, `Operator actions unavailable (${response.status})`));
    setActions(parseActions(body));
    setError('');
  }, [base, enabled, scanId]);

  useEffect(() => {
    if (!enabled || !scanId) { setActions([]); return; }
    const abort = new AbortController();
    void load(abort.signal).catch(error => {
      if (!abort.signal.aborted) setError(error instanceof Error ? error.message : 'Operator actions unavailable');
    });
    const timer = ['running', 'paused'].includes(scanStatus)
      ? window.setInterval(() => void load(abort.signal).catch(() => undefined), 3000)
      : undefined;
    return () => { abort.abort(); if (timer !== undefined) window.clearInterval(timer); };
  }, [enabled, load, scanId, scanStatus]);

  const acknowledge = async (actionId: string) => {
    if (busy) return;
    setBusy(actionId); setError('');
    try {
      const response = await fetch(new URL(
        `/api/v1/scans/${encodeURIComponent(scanId)}/operator-actions/${encodeURIComponent(actionId)}/acknowledge`, base,
      ), {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operator: 'dashboard-operator' }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(apiErrorMessage(body.detail, `Action update failed (${response.status})`));
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Action update failed');
    } finally { setBusy(''); }
  };

  return { actions, busy, error, acknowledge };
}
