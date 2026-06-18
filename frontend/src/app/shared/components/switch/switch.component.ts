import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  computed,
} from '@angular/core';

/**
 * DS switch / toggle — `ui-switch`. A `role="switch"` button (not a checkbox)
 * with track + sliding thumb; space/enter toggle it. Two-way `checked` model;
 * project the visible label as content.
 */
@Component({
  selector: 'app-switch',
  template: `
    <button
      type="button"
      role="switch"
      [attr.aria-checked]="checked()"
      [disabled]="disabled()"
      [attr.data-testid]="testId()"
      class="inline-flex cursor-pointer items-center gap-2.5 font-sans text-[13px] text-fg select-none disabled:cursor-not-allowed disabled:opacity-40"
      (click)="toggle()"
    >
      <span [class]="trackClasses()" aria-hidden="true">
        <span [class]="thumbClasses()"></span>
      </span>
      <ng-content />
    </button>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SwitchComponent {
  readonly checked = model(false);
  readonly disabled = input(false);
  readonly testId = input<string | null>(null);

  protected readonly trackClasses = computed(() =>
    [
      'relative inline-flex h-5 w-[34px] shrink-0 cursor-pointer items-center rounded-full border',
      'transition-colors duration-[120ms] disabled:cursor-not-allowed',
      this.checked() ? 'border-brand bg-brand' : 'border-border bg-overlay',
    ].join(' '),
  );

  protected readonly thumbClasses = computed(() =>
    [
      'absolute left-px size-[14px] rounded-full transition-transform duration-[120ms]',
      this.checked()
        ? 'translate-x-[14px] bg-primary-foreground'
        : 'bg-fg-muted',
    ].join(' '),
  );

  protected toggle(): void {
    if (!this.disabled()) {
      this.checked.update((v) => !v);
    }
  }
}
