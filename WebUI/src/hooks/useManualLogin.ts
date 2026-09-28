import { useEffect, useState } from 'react';
import { canConfirmManualLogin, parseManualLogin, type ManualLoginRequest } from '../lib/manualLogin';
import { apiErrorMessage } from '../lib/transport';

export function useManualLogin(scanId: string, scanStatus: string, enabled: boolean) {
  const [request, setRequest] = useState<ManualLoginRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ scanId: string; message: string } | null>(null);
  const base = import.meta.env.VITE_API_BASE || location.origin;

  useEffect(() => {
    if (!enabled || !scanId) return;
    const abort = new AbortController();
    let loading = false;
    const load = async () => {
      if (loading || abort.signal.aborted) return;
      loading = true;
      try {
        const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/manual-login`, base),
          { credentials: 'same-origin', cache: 'no-store', signal: abort.signal });
        if (!response.ok) throw new Error(`Login status unavailable (${response.status})`);
        const value = parseManualLogin(await response.json());
        if (!abort.signal.aborted) { setRequest(value); setFailure(null); }
      } catch (error) {
        if (!abort.signal.aborted) setFailure({ scanId, message: error instanceof Error ? error.message : 'Login status unavailable' });
      } finally { loading = false; }
    };
    void load();
    const timer = scanStatus === 'running' || scanStatus === 'paused' ? window.setInterval(() => void load(), 1000) : undefined;
    return () => { abort.abort(); if (timer !== undefined) window.clearInterval(timer); };
  }, [base, enabled, scanId, scanStatus]);

  const confirm = async () => {
    if (busy || !canConfirmManualLogin(request, scanId, scanStatus)) return;
    setBusy(true); setFailure(null);
    try {
      const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/manual-login/confirm`, base), {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: request!.request_id }),
      });
      const value = await response.json();
      if (!response.ok) throw new Error(apiErrorMessage(value.detail, `Login confirmation failed (${response.status})`));
      setRequest(parseManualLogin(value));
    } catch (error) {
      setFailure({ scanId, message: error instanceof Error ? error.message : 'Login confirmation failed' });
    } finally { setBusy(false); }
  };

  return {
    request: enabled && request?.scan_id === scanId ? request : null,
    busy, error: failure?.scanId === scanId ? failure.message : '', confirm,
    canConfirm: enabled && canConfirmManualLogin(request, scanId, scanStatus),
  };
}
