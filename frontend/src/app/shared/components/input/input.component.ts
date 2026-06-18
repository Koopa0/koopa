import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  computed,
} from '@angular/core';

export type InputSize = 'sm' | 'md' | 'lg';

const SIZE_CLASSES: Record<InputSize, string> = {
  sm: 'px-2 py-1.5 text-xs',
  md: 'px-2.5 py-2 text-[13px]',
  lg: 'px-3 py-2.5 text-sm',
};

/**
 * DS text input — `ui-input`. Presentational, Signal-Forms friendly: forwards
 * its value through a two-way `value` model and emits on native input. Set
 * `invalid` to surface the error border (also reflected via aria-invalid).
 */
@Component({
  selector: 'app-input',
  template: `
    <input
      [type]="type()"
      [value]="value()"
      [placeholder]="placeholder()"
      [disabled]="disabled()"
      [attr.aria-invalid]="invalid() || null"
      [attr.data-testid]="testId()"
      [class]="classes()"
      (input)="onInput($event)"
    />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class InputComponent {
  readonly value = model('');
  readonly type = input<
    'text' | 'email' | 'password' | 'search' | 'tel' | 'url' | 'number'
  >('text');
  readonly placeholder = input('');
  readonly disabled = input(false);
  readonly invalid = input(false);
  readonly mono = input(false);
  readonly size = input<InputSize>('md');
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() =>
    [
      'w-full rounded-sm border border-border bg-elevated text-fg leading-normal',
      'placeholder:text-fg-faint transition-colors duration-[120ms]',
      'hover:border-border-strong focus:border-brand focus:bg-panel focus:outline-hidden',
      'aria-invalid:border-error',
      'disabled:opacity-40 disabled:cursor-not-allowed',
      this.mono() ? 'font-mono' : 'font-sans',
      SIZE_CLASSES[this.size()],
    ].join(' '),
  );

  protected onInput(event: Event): void {
    this.value.set((event.target as HTMLInputElement).value);
  }
}
