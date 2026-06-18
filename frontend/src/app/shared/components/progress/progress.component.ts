import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type ProgressTone = 'brand' | 'success' | 'warn';

const FILL_CLASSES: Record<ProgressTone, string> = {
  brand: 'bg-brand',
  success: 'bg-success',
  warn: 'bg-warn',
};

/**
 * DS progress bar — `ui-progress`. Thin track with an animated fill whose
 * colour follows the tone. Exposes the full progressbar ARIA contract.
 */
@Component({
  selector: 'app-progress',
  template: `
    <div
      class="h-1.5 w-full overflow-hidden rounded-full bg-overlay"
      role="progressbar"
      [attr.aria-valuenow]="clamped()"
      aria-valuemin="0"
      aria-valuemax="100"
      [attr.aria-label]="label()"
      [attr.data-testid]="testId()"
    >
      <div
        class="h-full rounded-full transition-[width] duration-200"
        [class]="fillClasses()"
        [style.width.%]="clamped()"
      ></div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProgressComponent {
  readonly value = input.required<number>();
  readonly tone = input<ProgressTone>('brand');
  readonly label = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected readonly clamped = computed(() =>
    Math.max(0, Math.min(100, this.value())),
  );

  protected readonly fillClasses = computed(() => FILL_CLASSES[this.tone()]);
}
