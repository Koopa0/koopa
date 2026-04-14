import {
  DestroyRef,
  Injectable,
  PLATFORM_ID,
  computed,
  inject,
  signal,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { rxResource } from '@angular/core/rxjs-interop';
import type { SystemHealth } from '../models/admin.model';
import { SystemService } from './system.service';

export type RibbonStatus = 'ok' | 'warn' | 'error';

export interface RibbonToken {
  label: string;
  status: RibbonStatus;
}

export interface RibbonTokens {
  pipeline: RibbonToken;
  feeds: RibbonToken;
  aiBudget: RibbonToken;
}

const POLL_INTERVAL_MS = 30_000;

// Pure derivation helpers, exported for direct unit testing without
// needing to drain the rxResource subscription scheduler.

export function derivePipeline(h: SystemHealth): RibbonToken {
  const failed = h.pipelines.failed;
  if (failed === 0) {
    return { label: 'pipeline ok', status: 'ok' };
  }
  return {
    label: `pipeline ${failed} failed`,
    status: failed >= 3 ? 'error' : 'warn',
  };
}

export function deriveFeeds(h: SystemHealth): RibbonToken {
  const total = h.feeds.total;
  if (total === 0) {
    return { label: 'feeds —', status: 'ok' };
  }
  const pct = Math.round((h.feeds.healthy / total) * 100);
  let status: RibbonStatus = 'ok';
  if (pct < 90) status = 'error';
  else if (pct < 100) status = 'warn';
  return { label: `feeds ${pct}%`, status };
}

export function deriveBudget(h: SystemHealth): RibbonToken {
  const limit = h.ai_budget.daily_limit;
  if (limit <= 0) {
    return { label: 'ai —', status: 'ok' };
  }
  const pct = Math.round((h.ai_budget.today_tokens / limit) * 100);
  let status: RibbonStatus = 'ok';
  if (pct >= 90) status = 'error';
  else if (pct >= 70) status = 'warn';
  return { label: `ai ${pct}%`, status };
}

/**
 * Polls /api/admin/system/health every {@link POLL_INTERVAL_MS} and
 * derives three traffic-light tokens for the admin status ribbon. Pauses
 * when the tab is hidden via the Page Visibility API and resumes on
 * the next visibility change. SSR returns null without firing any HTTP
 * — there is no point fetching system health during prerender.
 *
 * Phase 1 reuses the existing health endpoint instead of shipping a
 * lean /api/admin/system/ribbon endpoint. The payload is small enough
 * for the single-user case; a dedicated endpoint can land later if the
 * full health response becomes a bandwidth concern.
 */
@Injectable({ providedIn: 'root' })
export class RibbonService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);
  private readonly systemService = inject(SystemService);

  private readonly visible = signal<boolean>(true);
  private readonly tick = signal<number>(0);

  protected readonly resource = rxResource<SystemHealth, number>({
    params: () => this.tick(),
    stream: () => this.systemService.getHealth(),
  });

  readonly health = this.resource.value;
  readonly isLoading = computed(() => this.resource.status() === 'loading');
  readonly hasError = computed(() => this.resource.status() === 'error');

  readonly tokens = computed<RibbonTokens | null>(() => {
    const h = this.resource.value();
    if (!h) return null;
    return {
      pipeline: derivePipeline(h),
      feeds: deriveFeeds(h),
      aiBudget: deriveBudget(h),
    };
  });

  constructor() {
    if (!isPlatformBrowser(this.platformId)) return;

    const onVisibility = (): void => {
      const nowVisible = !document.hidden;
      this.visible.set(nowVisible);
      // Refresh immediately on regaining focus so the ribbon is not stale.
      if (nowVisible) {
        this.tick.update((n) => n + 1);
      }
    };
    document.addEventListener('visibilitychange', onVisibility);

    const intervalId = setInterval(() => {
      if (this.visible()) {
        this.tick.update((n) => n + 1);
      }
    }, POLL_INTERVAL_MS);

    this.destroyRef.onDestroy(() => {
      document.removeEventListener('visibilitychange', onVisibility);
      clearInterval(intervalId);
    });
  }
}
