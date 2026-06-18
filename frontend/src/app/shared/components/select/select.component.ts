import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  computed,
} from '@angular/core';

export interface SelectOption {
  readonly value: string;
  readonly label: string;
}

export type SelectSize = 'sm' | 'md' | 'lg';

const SIZE_CLASSES: Record<SelectSize, string> = {
  sm: 'py-1.5 pl-2 pr-8 text-xs',
  md: 'py-2 pl-2.5 pr-9 text-[13px]',
  lg: 'py-2.5 pl-3 pr-9 text-sm',
};

/**
 * DS native select — `ui-select`. A styled native `<select>` (appearance-none
 * + custom chevron) so keyboard/screen-reader behaviour stays native. Two-way
 * `value` model; pass `options` as `{ value, label }[]`.
 */
@Component({
  selector: 'app-select',
  template: `
    <div class="relative w-full">
      <select
        [value]="value()"
        [disabled]="disabled()"
        [attr.aria-label]="ariaLabel() || placeholder() || null"
        [attr.aria-invalid]="invalid() || null"
        [attr.data-testid]="testId()"
        [class]="classes()"
        (change)="onChange($event)"
      >
        @if (placeholder()) {
          <option value="" disabled hidden>{{ placeholder() }}</option>
        }
        @for (opt of options(); track opt.value) {
          <option [value]="opt.value">{{ opt.label }}</option>
        }
      </select>
      <span
        class="pointer-events-none absolute inset-y-0 right-2.5 flex items-center text-fg-subtle"
        aria-hidden="true"
      >
        <svg
          width="14"
          height="14"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path d="m4 6 4 4 4-4" />
        </svg>
      </span>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SelectComponent {
  readonly value = model('');
  readonly options = input<readonly SelectOption[]>([]);
  readonly placeholder = input('');
  readonly ariaLabel = input<string | null>(null);
  readonly disabled = input(false);
  readonly invalid = input(false);
  readonly size = input<SelectSize>('md');
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() =>
    [
      'w-full appearance-none rounded-sm border border-border bg-elevated text-fg font-sans leading-normal',
      'transition-colors duration-[120ms] cursor-pointer',
      'hover:border-border-strong focus:border-brand focus:bg-panel focus:outline-hidden',
      'aria-invalid:border-error',
      'disabled:opacity-40 disabled:cursor-not-allowed',
      SIZE_CLASSES[this.size()],
    ].join(' '),
  );

  protected onChange(event: Event): void {
    this.value.set((event.target as HTMLSelectElement).value);
  }
}
