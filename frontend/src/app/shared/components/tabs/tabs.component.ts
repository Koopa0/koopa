import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
} from '@angular/core';

export interface TabItem {
  readonly id: string;
  readonly label: string;
  readonly disabled?: boolean;
}

/**
 * DS underline tabs — `ui-tabs`. Signal-driven: `active` is a two-way model.
 * Renders an ARIA tablist; the brand underline marks the selected tab.
 */
@Component({
  selector: 'app-tabs',
  template: `
    <div class="flex gap-0.5 border-b border-border" role="tablist">
      @for (tab of items(); track tab.id) {
        <button
          type="button"
          role="tab"
          [id]="'tab-' + tab.id"
          [attr.aria-selected]="tab.id === active()"
          [attr.tabindex]="tab.id === active() ? 0 : -1"
          [disabled]="tab.disabled || null"
          [attr.data-testid]="'tab-' + tab.id"
          class="-mb-px cursor-pointer border-b-2 border-transparent bg-transparent px-3.5 py-2.5 font-sans text-[13px] text-fg-subtle transition-colors duration-[120ms] hover:text-fg-muted disabled:pointer-events-none disabled:opacity-40 aria-selected:border-b-brand aria-selected:text-fg"
          (click)="select(tab)"
        >
          {{ tab.label }}
        </button>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TabsComponent {
  readonly items = input.required<readonly TabItem[]>();
  readonly active = model.required<string>();

  protected select(tab: TabItem): void {
    if (!tab.disabled) {
      this.active.set(tab.id);
    }
  }
}
