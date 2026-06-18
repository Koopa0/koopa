import { Component, ChangeDetectionStrategy, input } from '@angular/core';

/**
 * DS hex tile — `ui-hextile`. Leading brand-tinted tile used to front an icon
 * (project a ~22px icon as content). Approximated as a rounded brand square
 * rather than a true hexagon SVG — visually a brand-muted chip with the
 * AA-safe `text-brand-strong` foreground for the tint background.
 */
@Component({
  selector: 'app-hextile',
  template: `
    <span
      class="inline-flex size-10 items-center justify-center rounded-md bg-brand-muted text-brand-strong [&_svg]:size-[22px]"
      aria-hidden="true"
      [attr.data-testid]="testId()"
    >
      <ng-content />
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HextileComponent {
  readonly testId = input<string | null>(null);
}
