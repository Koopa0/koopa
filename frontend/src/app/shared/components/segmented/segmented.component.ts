import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
} from '@angular/core';

export interface SegmentedItem {
  readonly id: string;
  readonly label: string;
  readonly disabled?: boolean;
}

/**
 * DS enclosed segmented control — `ui-segmented`. Signal-driven: `active` is a
 * two-way model. Renders a `role=group` of toggle buttons; the active segment
 * gets the overlay surface via `aria-pressed`.
 */
@Component({
  selector: 'app-segmented',
  template: `
    <div
      class="inline-flex gap-0.5 rounded-sm border border-border bg-elevated p-0.5"
      role="group"
      [attr.aria-label]="ariaLabel()"
      [attr.data-testid]="testId()"
    >
      @for (item of items(); track item.id) {
        <button
          type="button"
          [attr.aria-pressed]="item.id === active()"
          [disabled]="item.disabled || null"
          [attr.aria-disabled]="item.disabled || null"
          [attr.data-testid]="'segmented-' + item.id"
          class="cursor-pointer rounded-[2px] bg-transparent px-3 py-[5px] font-sans text-[13px] leading-3 font-medium text-fg-subtle transition-colors duration-[120ms] hover:text-fg-muted disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-40 aria-pressed:bg-overlay aria-pressed:text-fg"
          (click)="select(item)"
        >
          {{ item.label }}
        </button>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SegmentedComponent {
  readonly items = input.required<readonly SegmentedItem[]>();
  readonly active = model.required<string>();
  readonly ariaLabel = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected select(item: SegmentedItem): void {
    if (!item.disabled) {
      this.active.set(item.id);
    }
  }
}
