import {
  Component,
  ChangeDetectionStrategy,
  input,
  output,
  computed,
} from '@angular/core';

/**
 * DS filter chip — `ui-chip`. Mono, toggleable via `active` (reflected as
 * `aria-pressed`), optionally `removable` with an `×` button that emits
 * `removed`. The chip itself is a `role="button"` toggle.
 */
@Component({
  selector: 'app-chip',
  template: `
    <span
      [attr.data-active]="active() ? 'true' : null"
      [attr.data-testid]="testId()"
      [class]="classes()"
    >
      <ng-content />
      @if (removable()) {
        <button
          type="button"
          aria-label="Remove"
          [attr.data-testid]="testId() ? testId() + '-remove' : null"
          class="-mr-0.5 inline-flex size-3.5 cursor-pointer items-center justify-center rounded-full leading-none text-current transition-colors duration-[120ms] hover:bg-(--accent-faint)"
          (click)="onRemove($event)"
        >
          <span aria-hidden="true">&times;</span>
        </button>
      }
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ChipComponent {
  readonly active = input(false);
  readonly removable = input(false);
  readonly testId = input<string | null>(null);

  readonly removed = output<void>();

  protected readonly classes = computed(() =>
    [
      'inline-flex cursor-pointer items-center gap-1 rounded-sm border px-2.5 py-1',
      'font-mono text-[11px] leading-none transition-colors duration-[120ms]',
      this.active()
        ? 'border-transparent bg-brand-muted text-brand-strong'
        : 'border-border-faint bg-elevated text-fg-subtle hover:border-border hover:text-fg-muted',
    ].join(' '),
  );

  protected onRemove(event: Event): void {
    event.stopPropagation();
    this.removed.emit();
  }
}
