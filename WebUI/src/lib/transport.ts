export function resolveTransportMode(configured: string | undefined, search: string): 'live' | 'demo' {
  return configured === 'live' && new URLSearchParams(search).get('sample') !== '1' ? 'live' : 'demo';
}

export function apiErrorMessage(detail: unknown, fallback: string): string {
  const messages = (Array.isArray(detail) ? detail : [detail]).flatMap(item => {
    let message: unknown = item;
    if (typeof item === 'object' && item !== null) {
      const error = item as Record<string, unknown>;
      message = typeof error.msg === 'string' ? error.msg : error.message;
    }
    if (typeof message !== 'string' || !message.trim()) return [];
    return [message.trim().replace(/^Value error,\s*/, '')];
  });
  return messages.join('\n') || fallback;
}
