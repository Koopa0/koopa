import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

type BadgeVariant = 'success' | 'warning' | 'info' | 'danger' | 'neutral';

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
  success: 'border-success/30 bg-success-bg text-success',
  warning: 'border-warn/30 bg-warn-bg text-warn',
  info: 'border-info/30 bg-info-bg text-info',
  danger: 'border-error/30 bg-error-bg text-error',
  neutral: 'border-border bg-overlay text-fg-subtle',
};

@Component({
  selector: 'app-status-badge',
  standalone: true,
  template: `
    <span
      class="inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-[11px] tracking-wide uppercase"
      [class]="variantClass()"
    >
      <ng-content />
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StatusBadgeComponent {
  readonly variant = input<BadgeVariant>('neutral');

  protected readonly variantClass = computed(
    () => VARIANT_CLASSES[this.variant()],
  );
}
