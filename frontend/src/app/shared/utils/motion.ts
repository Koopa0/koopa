/**
 * Safe prefers-reduced-motion check. Returns false when matchMedia is
 * unavailable (SSR or the jsdom test environment) so animation code degrades
 * to "motion allowed" instead of throwing on `window.matchMedia(...)`. Callers
 * still guard `isPlatformBrowser` before doing real DOM work; this only makes
 * the media-query read non-throwing across environments.
 */
export function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}
