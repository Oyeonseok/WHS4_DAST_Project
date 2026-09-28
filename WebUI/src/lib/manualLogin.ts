export type ManualLoginRequest = {
  scan_id: string;
  request_id: string;
  target_origin: string;
  status: 'waiting' | 'confirmed' | 'accepted' | 'expired' | 'failed';
  expires_at: number;
  problem: string | null;
  auth_state: 'operator_confirmed' | null;
};

export function parseManualLogin(value: unknown): ManualLoginRequest | null {
  if (!value || typeof value !== 'object') return null;
  const request = (value as Record<string, unknown>).manual_login;
  if (!request || typeof request !== 'object') return null;
  const data = request as Record<string, unknown>;
  if (typeof data.scan_id !== 'string' || typeof data.request_id !== 'string'
      || !/^[a-f0-9]{32}$/.test(data.request_id) || typeof data.target_origin !== 'string'
      || typeof data.expires_at !== 'number' || !Number.isFinite(data.expires_at)
      || !['waiting', 'confirmed', 'accepted', 'expired', 'failed'].includes(String(data.status))
      || !(data.problem === null || typeof data.problem === 'string')
      || !(data.auth_state === null || data.auth_state === 'operator_confirmed')) return null;
  return data as ManualLoginRequest;
}

export function canConfirmManualLogin(request: ManualLoginRequest | null, scanId: string,
                                     scanStatus: string, now = Date.now() / 1000): boolean {
  return request?.scan_id === scanId && scanStatus === 'running'
    && request.status === 'waiting' && request.expires_at > now;
}
