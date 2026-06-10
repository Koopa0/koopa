import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  PLATFORM_ID,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { DatePipe, isPlatformBrowser } from '@angular/common';
import { RouterLink } from '@angular/router';
import type { ActiveSession } from './today.service';

const TICK_MS = 1000;
const SECONDS_PER_HOUR = 3600;
const SECONDS_PER_MINUTE = 60;

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

/** hh:mm:ss elapsed since `startedAt`, clamped at zero for clock skew. */
function formatElapsed(startedAt: string, nowMs: number): string {
  const total = Math.max(0, Math.floor((nowMs - Date.parse(startedAt)) / 1000));
  const hours = Math.floor(total / SECONDS_PER_HOUR);
  const minutes = Math.floor((total % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE);
  const seconds = total % SECONDS_PER_MINUTE;
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
}

/**
 * The open learning session — the single "now" accent on the Today page.
 * Renders the live pulse label, domain, mode chip, an elapsed timer
 * ticking once per second (browser only), and a link into the session
 * timeline. Hosted only when the brief carries an active_session.
 */
@Component({
  selector: 'app-today-session-card',
  standalone: true,
  imports: [DatePipe, RouterLink],
  template: `
    <section
      class="relative overflow-hidden rounded-md border border-brand-muted bg-panel p-4 before:absolute before:inset-y-0 before:left-0 before:w-0.5 before:bg-brand"
      data-testid="today-session"
    >
      <h2
        class="mb-2 flex items-center gap-2 font-mono text-[10px] tracking-wide text-brand uppercase"
      >
        <span
          class="size-1.5 animate-pulse rounded-full bg-brand"
          aria-hidden="true"
        ></span>
        Active session
      </h2>
      <p class="font-display text-base font-semibold text-fg">
        {{ session().domain }}
      </p>
      <p
        class="mt-1.5 flex items-center gap-2 font-mono text-[11px] text-fg-subtle"
      >
        <span class="rounded-sm bg-elevated px-1.5 py-0.5">
          {{ session().mode }}
        </span>
        <span>since {{ session().started_at | date: 'shortTime' }}</span>
      </p>
      <p
        class="mt-3 font-display text-3xl font-semibold text-fg tabular-nums"
        data-testid="today-session-elapsed"
      >
        {{ elapsed() }}
      </p>
      <a
        [routerLink]="['/admin/learning/sessions', session().id]"
        class="mt-3 inline-flex items-center rounded-sm border border-border bg-elevated px-2.5 py-1 text-xs text-fg-muted transition-colors hover:border-brand hover:text-brand"
      >
        Open session →
      </a>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TodaySessionCardComponent {
  readonly session = input.required<ActiveSession>();

  private readonly platformId = inject(PLATFORM_ID);
  private readonly nowMs = signal(Date.now());

  protected readonly elapsed = computed(() =>
    formatElapsed(this.session().started_at, this.nowMs()),
  );

  constructor() {
    if (isPlatformBrowser(this.platformId)) {
      const timer = setInterval(() => this.nowMs.set(Date.now()), TICK_MS);
      inject(DestroyRef).onDestroy(() => clearInterval(timer));
    }
  }
}
