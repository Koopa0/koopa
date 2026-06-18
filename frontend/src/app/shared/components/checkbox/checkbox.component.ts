import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
} from '@angular/core';

/**
 * DS checkbox — `ui-checkbox`. Visually-hidden native input paired with a
 * custom box (so it stays keyboard/AT operable and form-associable). Project
 * the label as content. Two-way `checked` model.
 */
@Component({
  selector: 'app-checkbox',
  template: `
    <label
      class="inline-flex cursor-pointer items-center gap-2 font-sans text-[13px] text-fg select-none"
      [class.opacity-40]="disabled()"
      [class.cursor-not-allowed]="disabled()"
    >
      <input
        type="checkbox"
        class="peer sr-only"
        [checked]="checked()"
        [disabled]="disabled()"
        [attr.aria-invalid]="invalid() || null"
        [attr.data-testid]="testId()"
        (change)="onChange($event)"
      />
      <span
        class="flex size-4 shrink-0 items-center justify-center rounded-sm border border-border-strong bg-elevated transition-colors duration-[120ms] peer-checked:border-brand peer-checked:bg-brand peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-brand peer-aria-[invalid=true]:border-error"
        aria-hidden="true"
      >
        <svg
          class="size-3 text-primary-foreground opacity-0 transition-opacity duration-[120ms] peer-checked:opacity-100"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          stroke-width="2.5"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path d="m3.5 8.5 3 3 6-7" />
        </svg>
      </span>
      <ng-content />
    </label>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CheckboxComponent {
  readonly checked = model(false);
  readonly disabled = input(false);
  readonly invalid = input(false);
  readonly testId = input<string | null>(null);

  protected onChange(event: Event): void {
    this.checked.set((event.target as HTMLInputElement).checked);
  }
}
