export type ManualLoginRequest = {
  scan_id: string;
  request_id: string;
  target_origin: string;
  status: 'waiting' | 'confirmed' | 'accepted' | 'expired' | 'failed';
  expires_at: number;
  problem: string | null;
  auth_state: 'operator_confirmed' | null;
  action_kind?: 'login' | 'recon_login' | 'mfa' | 'captcha' | 'access';
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
      || !(data.action_kind === undefined || ['login', 'recon_login', 'mfa', 'captcha', 'access'].includes(String(data.action_kind)))
      || !(data.auth_state === null || data.auth_state === 'operator_confirmed')) return null;
  return data as ManualLoginRequest;
}

export function manualActionLabel(request: ManualLoginRequest, language: 'ko' | 'en'): string {
  const kind = request.problem === 'mfa_required' ? 'mfa' : request.problem === 'captcha_required' ? 'captcha' : request.action_kind || 'login';
  const labels = {
    login: ['브라우저 로그인', 'Browser login'], recon_login: ['정찰 중 로그인', 'Login during Recon'],
    mfa: ['MFA 인증', 'MFA verification'], captcha: ['CAPTCHA 확인', 'CAPTCHA verification'],
    access: ['사이트 접근 확인', 'Site access confirmation'],
  };
  return labels[kind][language === 'ko' ? 0 : 1];
}

export function canConfirmManualLogin(request: ManualLoginRequest | null, scanId: string,
                                     scanStatus: string, now = Date.now() / 1000): boolean {
  return request?.scan_id === scanId && scanStatus === 'running'
    && request.status === 'waiting' && request.expires_at > now;
}
