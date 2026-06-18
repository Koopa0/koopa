import {
  Component,
  ChangeDetectionStrategy,
  model,
  input,
} from '@angular/core';
import { A11yModule } from '@angular/cdk/a11y';

/**
 * DS right-side drawer — `ui-drawer`. Two-way `open` model drives a fixed
 * scrim + sliding panel. Slots: `[drawer-header]`, default body (scrollable),
 * `[drawer-footer]`. `role=dialog aria-modal`; focus is trapped while open and
 * ESC / scrim click close it. Rendered only while open.
 */
@Component({
  selector: 'app-drawer',
  imports: [A11yModule],
  template: `
    @if (open()) {
      <!-- Scrim -->
      <div
        class="fixed inset-0 z-50 bg-black/60"
        aria-hidden="true"
        [attr.data-testid]="testId() ? testId() + '-scrim' : null"
        (click)="close()"
      ></div>

      <!-- Panel -->
      <div
        class="fixed top-0 right-0 z-50 flex h-full w-[420px] max-w-[92vw] flex-col border-l border-border bg-panel shadow-[var(--shadow-2)]"
        role="dialog"
        aria-modal="true"
        [attr.aria-label]="ariaLabel()"
        [attr.aria-labelledby]="labelledBy()"
        [attr.data-testid]="testId()"
        cdkTrapFocus
        cdkTrapFocusAutoCapture
        (keydown.escape)="close()"
      >
        <div class="shrink-0 border-b border-border px-[18px] py-3.5">
          <ng-content select="[drawer-header]" />
        </div>

        <div class="min-h-0 flex-1 overflow-y-auto p-[18px]">
          <ng-content />
        </div>

        <div
          class="flex shrink-0 justify-end gap-3 border-t border-border px-[18px] py-3.5"
        >
          <ng-content select="[drawer-footer]" />
        </div>
      </div>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DrawerComponent {
  /** Two-way open state. */
  readonly open = model(false);
  readonly ariaLabel = input<string | null>(null);
  /** Id of an element inside `[drawer-header]` that titles the dialog. */
  readonly labelledBy = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected close(): void {
    this.open.set(false);
  }
}
