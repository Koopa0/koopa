import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg';

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary: 'bg-primary text-primary-foreground hover:bg-(--accent-strong)',
  secondary:
    'bg-elevated text-fg border-border hover:bg-overlay hover:border-border-strong active:bg-panel',
  ghost:
    'bg-transparent text-fg-muted hover:bg-overlay hover:text-fg active:bg-panel',
  danger: 'bg-error-bg text-error hover:bg-error/20 active:bg-error/25',
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  xs: 'gap-1.5 px-2 py-1 text-xs',
  sm: 'gap-1.5 px-2.5 py-1.5 text-[13px]',
  md: 'gap-2 px-3.5 py-2 text-[13px]',
  lg: 'gap-2 px-4.5 py-2.5 text-sm',
};

/**
 * DS button — `ui-btn`. Variants primary/secondary/ghost/danger, four sizes,
 * loading spinner, icon-only, full-width. Radius is r-sm (no pill, per DS).
 */
@Component({
  selector: 'app-button',
  template: `
    <button
      [type]="type()"
      [disabled]="disabled() || loading()"
      [attr.aria-busy]="loading() || null"
      [attr.data-testid]="testId()"
      [class]="classes()"
    >
      @if (loading()) {
        <span
          class="absolute size-[15px] animate-spin rounded-full border-2 border-transparent border-t-current"
          aria-hidden="true"
        ></span>
      }
      <span class="contents" [class.opacity-0]="loading()">
        <ng-content />
      </span>
    </button>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ButtonComponent {
  readonly variant = input<ButtonVariant>('secondary');
  readonly size = input<ButtonSize>('md');
  readonly type = input<'button' | 'submit' | 'reset'>('button');
  readonly disabled = input(false);
  readonly loading = input(false);
  readonly block = input(false);
  readonly iconOnly = input(false);
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() => {
    const icon = this.iconOnly()
      ? this.size() === 'sm'
        ? 'p-1.5'
        : 'p-2'
      : SIZE_CLASSES[this.size()];
    return [
      'relative inline-flex items-center justify-center font-sans font-semibold leading-none',
      'rounded-sm border border-transparent cursor-pointer whitespace-nowrap no-underline',
      'transition-colors duration-[120ms] disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none',
      '[&_svg]:size-4',
      this.block() ? 'w-full' : '',
      VARIANT_CLASSES[this.variant()],
      icon,
    ]
      .filter(Boolean)
      .join(' ');
  });
}
