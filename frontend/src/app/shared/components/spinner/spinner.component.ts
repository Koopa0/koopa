import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type SpinnerSize = 'sm' | 'md' | 'lg';

const SIZE_CLASSES: Record<SpinnerSize, string> = {
  sm: 'size-3.5', // 14px
  md: 'size-[18px]', // 18px
  lg: 'size-[26px]', // 26px
};

/**
 * DS spinner — `ui-spinner`. A ring loader: the accent track top-segment spins
 * over a faint overlay ring. role=status with an accessible label. Honors
 * global reduced-motion (handled in styles.css).
 */
@Component({
  selector: 'app-spinner',
  template: `
    <span
      class="inline-block animate-spin rounded-full border-2 border-overlay border-t-(--accent)"
      [class]="sizeClass()"
      role="status"
      [attr.aria-label]="label()"
      [attr.data-testid]="testId() ?? 'spinner'"
    ></span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SpinnerComponent {
  readonly size = input<SpinnerSize>('md');
  readonly label = input('Loading');
  readonly testId = input<string | null>(null);

  protected readonly sizeClass = computed(() => SIZE_CLASSES[this.size()]);
}
