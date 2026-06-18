import { Component, ChangeDetectionStrategy, input } from '@angular/core';

/**
 * DS inline `#hashtag` tag — `ui-tag`. Mono, subtle. Renders an `<a>` when
 * `href` is set (brand on hover), otherwise a plain `<span>`. The label is
 * the projected content.
 */
@Component({
  selector: 'app-tag',
  template: `
    <a
      [attr.href]="href()"
      [attr.data-testid]="testId()"
      class="font-mono text-[11px] text-fg-subtle no-underline transition-colors duration-[120ms] hover:text-brand"
      ><ng-content
    /></a>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TagComponent {
  readonly href = input<string | null>(null);
  readonly testId = input<string | null>(null);
}
