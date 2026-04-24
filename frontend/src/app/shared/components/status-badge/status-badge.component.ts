import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

type BadgeVariant = 'success' | 'warning' | 'info' | 'danger' | 'neutral';

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
  success: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
  warning: 'border-amber-800 bg-amber-900/30 text-amber-400',
  info: 'border-sky-800 bg-sky-900/30 text-sky-400',
  danger: 'border-red-800 bg-red-900/30 text-red-400',
  neutral: 'border-zinc-700 bg-zinc-800 text-zinc-400',
};

@Component({
  selector: 'app-status-badge',
  standalone: true,
  template: `
    <span
      class="inline-block rounded-full border px-2 py-0.5 text-xs"
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
