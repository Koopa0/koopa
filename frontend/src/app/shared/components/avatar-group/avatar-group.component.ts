import { Component, ChangeDetectionStrategy, input } from '@angular/core';

/**
 * DS avatar group — `ui-avatar-group`. Overlaps projected `app-avatar`
 * children with a panel-coloured ring, optionally capping the visible count
 * and appending a `+N` more bubble. The caller is responsible for projecting
 * only the avatars that should be shown; `max`/`total` drive the overflow
 * bubble label.
 */
@Component({
  selector: 'app-avatar-group',
  template: `
    <div
      class="flex items-center [&>app-avatar]:rounded-full [&>app-avatar]:ring-2 [&>app-avatar]:ring-bg [&>*:not(:first-child)]:-ml-2"
      [attr.data-testid]="testId()"
    >
      <ng-content />
      @if (overflow() > 0) {
        <span
          class="-ml-2 inline-flex size-8 shrink-0 items-center justify-center rounded-full bg-elevated font-display text-xs font-semibold text-fg-muted ring-2 ring-bg select-none"
          [attr.data-testid]="testId() ? testId() + '-overflow' : null"
        >
          +{{ overflow() }}
        </span>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AvatarGroupComponent {
  /** Number of hidden avatars to surface in the `+N` bubble. */
  readonly overflow = input(0);
  readonly testId = input<string | null>(null);
}
