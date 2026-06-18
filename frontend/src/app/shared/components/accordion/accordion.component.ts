import { Component, ChangeDetectionStrategy } from '@angular/core';

/**
 * DS accordion container — `ui-accordion`. A bordered, r-md surface that wraps
 * one or more `app-accordion-item` projected via content. Each item owns its
 * own open/closed state (WAI-ARIA accordion pattern).
 */
@Component({
  selector: 'app-accordion',
  template: `
    <div
      class="divide-y divide-border-faint overflow-hidden rounded-md border border-border bg-panel"
      [attr.data-testid]="'accordion'"
    >
      <ng-content />
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AccordionComponent {}
