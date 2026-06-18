import {
  Component,
  ChangeDetectionStrategy,
  input,
  linkedSignal,
} from '@angular/core';

let nextId = 0;

/**
 * DS accordion item — `ui-accordion-item`. A disclosure row: a full-width
 * trigger button (title + rotating chevron) toggling a projected panel.
 * Implements the WAI-ARIA accordion pattern (aria-expanded + region).
 */
@Component({
  selector: 'app-accordion-item',
  template: `
    <h3 class="m-0">
      <button
        type="button"
        [id]="triggerId"
        [attr.aria-expanded]="open()"
        [attr.aria-controls]="panelId"
        [attr.data-testid]="testId() ?? 'accordion-trigger'"
        class="flex w-full cursor-pointer items-center justify-between gap-3 bg-transparent px-4 py-3.5 text-left font-sans text-sm font-medium text-fg transition-colors duration-[120ms] hover:bg-overlay disabled:cursor-not-allowed disabled:opacity-40"
        [disabled]="disabled() || null"
        (click)="toggle()"
      >
        <span>{{ title() }}</span>
        <svg
          class="size-4 shrink-0 text-fg-faint transition-transform duration-[120ms]"
          [class.rotate-180]="open()"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>
    </h3>
    @if (open()) {
      <div
        [id]="panelId"
        role="region"
        [attr.aria-labelledby]="triggerId"
        [attr.data-testid]="'accordion-panel'"
        class="px-4 pb-4 font-sans text-[13px] leading-normal text-fg-muted"
      >
        <ng-content />
      </div>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AccordionItemComponent {
  readonly title = input.required<string>();
  readonly disabled = input(false);
  readonly defaultOpen = input(false);
  readonly testId = input<string | null>(null);

  private readonly uid = nextId++;
  protected readonly triggerId = `accordion-trigger-${this.uid}`;
  protected readonly panelId = `accordion-panel-${this.uid}`;

  /** Writable open state, seeded from `defaultOpen`. */
  protected readonly open = linkedSignal(() => this.defaultOpen());

  protected toggle(): void {
    if (this.disabled()) {
      return;
    }
    this.open.update((v) => !v);
  }
}
