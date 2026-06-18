import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type BadgeTone =
  | 'neutral'
  | 'brand'
  | 'success'
  | 'warn'
  | 'error'
  | 'info';

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: 'bg-elevated text-fg-muted border-border-faint',
  brand: 'bg-brand-muted text-brand-strong border-transparent',
  success: 'bg-success-bg text-success border-transparent',
  warn: 'bg-warn-bg text-warn border-transparent',
  error: 'bg-error-bg text-error border-transparent',
  info: 'bg-info-bg text-info border-transparent',
};

/**
 * DS generic badge — `ui-badge` (sans, sentence-case label). For lifecycle
 * enums (draft/review/published…) use the mono `app-status-badge` instead.
 */
@Component({
  selector: 'app-badge',
  template: `
    <span [class]="classes()" [attr.data-testid]="testId()">
      <ng-content />
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BadgeComponent {
  readonly tone = input<BadgeTone>('neutral');
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() =>
    [
      'inline-flex items-center gap-1.5 rounded-sm border px-2 py-[3px]',
      'font-sans text-[11px] leading-none font-medium',
      TONE_CLASSES[this.tone()],
    ].join(' '),
  );
}
