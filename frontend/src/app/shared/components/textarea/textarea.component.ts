import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  computed,
} from '@angular/core';

export type TextareaSize = 'sm' | 'md' | 'lg';

const SIZE_CLASSES: Record<TextareaSize, string> = {
  sm: 'px-2 py-1.5 text-xs',
  md: 'px-2.5 py-2 text-[13px]',
  lg: 'px-3 py-2.5 text-sm',
};

/**
 * DS multi-line input — `ui-textarea`. Mirrors `app-input` (same surface,
 * border, focus + invalid states) but vertically resizable with a sensible
 * min height. Two-way `value` model; presentational/Signal-Forms friendly.
 */
@Component({
  selector: 'app-textarea',
  template: `
    <textarea
      [value]="value()"
      [placeholder]="placeholder()"
      [disabled]="disabled()"
      [rows]="rows()"
      [attr.aria-invalid]="invalid() || null"
      [attr.data-testid]="testId()"
      [class]="classes()"
      (input)="onInput($event)"
    ></textarea>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TextareaComponent {
  readonly value = model('');
  readonly placeholder = input('');
  readonly disabled = input(false);
  readonly invalid = input(false);
  readonly mono = input(false);
  readonly rows = input(3);
  readonly size = input<TextareaSize>('md');
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() =>
    [
      'w-full min-h-20 resize-y rounded-sm border border-border bg-elevated text-fg leading-normal',
      'placeholder:text-fg-subtle transition-colors duration-[120ms]',
      'hover:border-border-strong focus:border-brand focus:bg-panel focus:outline-hidden',
      'aria-invalid:border-error',
      'disabled:opacity-40 disabled:cursor-not-allowed disabled:resize-none',
      this.mono() ? 'font-mono' : 'font-sans',
      SIZE_CLASSES[this.size()],
    ].join(' '),
  );

  protected onInput(event: Event): void {
    this.value.set((event.target as HTMLTextAreaElement).value);
  }
}
