import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type StatTrend = 'up' | 'down' | 'flat';

const TREND_CLASSES: Record<StatTrend, string> = {
  up: 'text-success',
  down: 'text-error',
  flat: 'text-fg-subtle',
};

/**
 * DS stat / metric card — `ui-stat-card`. Mono uppercase label, oversized
 * display value, optional delta whose colour follows the trend direction.
 */
@Component({
  selector: 'app-stat-card',
  template: `
    <div
      class="flex flex-col gap-1.5 rounded-md border border-border bg-panel px-4 py-[14px]"
      [attr.data-testid]="testId()"
    >
      <span
        class="font-mono text-[11px] tracking-[0.04em] text-fg-subtle uppercase"
      >
        {{ label() }}
      </span>
      <span class="font-display text-[30px] leading-none font-semibold text-fg">
        {{ value() }}
      </span>
      @if (delta(); as d) {
        <span
          class="font-mono text-[11px] leading-none"
          [class]="trendClasses()"
        >
          {{ d }}
        </span>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StatCardComponent {
  readonly label = input.required<string>();
  readonly value = input.required<string | number>();
  readonly delta = input<string | null>(null);
  readonly trend = input<StatTrend>('flat');
  readonly testId = input<string | null>(null);

  protected readonly trendClasses = computed(() => TREND_CLASSES[this.trend()]);
}
