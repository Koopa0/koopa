import { Component, ChangeDetectionStrategy, input } from '@angular/core';

/**
 * DS keyboard key — `ui-kbd`. A `<kbd>` rendered as a physical-looking key
 * cap (thicker bottom border) on the elevated surface. The key glyph is the
 * projected content.
 */
@Component({
  selector: 'app-kbd',
  template: `
    <kbd
      [attr.data-testid]="testId()"
      class="rounded-sm border border-b-2 border-border bg-elevated px-1.5 py-0.5 font-mono text-[11px] leading-none text-fg-muted"
    >
      <ng-content />
    </kbd>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class KbdComponent {
  readonly testId = input<string | null>(null);
}
