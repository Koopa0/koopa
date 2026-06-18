import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type SkeletonVariant = 'text' | 'title' | 'circle' | 'block';

const VARIANT_CLASSES: Record<SkeletonVariant, string> = {
  text: 'h-3 w-full rounded-sm',
  title: 'h-5 w-1/2 rounded-sm',
  circle: 'size-10 rounded-full',
  block: 'h-24 w-full rounded-sm',
};

/**
 * DS skeleton placeholder — `ui-skeleton`. Pulsing surface block used while
 * content loads. Decorative only (aria-hidden); global reduced-motion already
 * disables the pulse.
 */
@Component({
  selector: 'app-skeleton',
  template: `
    <span
      class="block animate-pulse bg-elevated"
      [class]="variantClasses()"
      [style.width]="width()"
      [style.height]="height()"
      aria-hidden="true"
      [attr.data-testid]="testId()"
    ></span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SkeletonComponent {
  readonly variant = input<SkeletonVariant>('text');
  readonly width = input<string | null>(null);
  readonly height = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected readonly variantClasses = computed(
    () => VARIANT_CLASSES[this.variant()],
  );
}
