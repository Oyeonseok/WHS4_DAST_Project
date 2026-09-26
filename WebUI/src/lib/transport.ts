export function resolveTransportMode(configured: string | undefined, search: string): 'live' | 'demo' {
  return configured === 'live' && new URLSearchParams(search).get('sample') !== '1' ? 'live' : 'demo';
}
