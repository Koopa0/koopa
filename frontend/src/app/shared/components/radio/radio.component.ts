import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  computed,
} from '@angular/core';

/**
 * DS radio — `ui-radio`. Visually-hidden native input + custom round box with
 * an inner dot when selected. Group several by sharing `name` and binding the
 * same two-way `groupValue` model; each radio carries its own `value`.
 */
@Component({
  selector: 'app-radio',
  template: `
    <label
      class="inline-flex cursor-pointer items-center gap-2 font-sans text-[13px] text-fg select-none"
      [class.opacity-40]="disabled()"
      [class.cursor-not-allowed]="disabled()"
    >
      <input
        type="radio"
        class="peer sr-only"
        [name]="name()"
        [value]="value()"
        [checked]="selected()"
        [disabled]="disabled()"
        [attr.data-testid]="testId()"
        (change)="onChange()"
      />
      <span
        class="flex size-4 shrink-0 items-center justify-center rounded-full border border-border-strong bg-elevated transition-colors duration-[120ms] peer-checked:border-brand peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-brand"
        aria-hidden="true"
      >
        <span
          class="size-2 rounded-full bg-brand opacity-0 transition-opacity duration-[120ms] peer-checked:opacity-100"
        ></span>
      </span>
      <ng-content />
    </label>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RadioComponent {
  readonly groupValue = model<string>('');
  readonly value = input.required<string>();
  readonly name = input.required<string>();
  readonly disabled = input(false);
  readonly testId = input<string | null>(null);

  protected readonly selected = computed(
    () => this.groupValue() === this.value(),
  );

  protected onChange(): void {
    this.groupValue.set(this.value());
  }
}
