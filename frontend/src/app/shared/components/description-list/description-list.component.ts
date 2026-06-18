import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export interface DescriptionRow {
  readonly term: string;
  readonly desc: string;
}

/**
 * DS description list — `ui-description-list`. Renders term/description pairs in
 * a `<dl>` grid. Default: fixed 180px term column with hairline-separated rows.
 * `inline` collapses each pair to a compact `max-content / 1fr` two-column row.
 */
@Component({
  selector: 'app-description-list',
  template: `
    <dl [class]="listClasses()" [attr.data-testid]="'description-list'">
      @for (row of rows(); track row.term) {
        @if (inline()) {
          <dt class="font-sans text-[13px] text-fg-subtle">{{ row.term }}</dt>
          <dd class="m-0 font-sans text-[13px] text-fg">{{ row.desc }}</dd>
        } @else {
          <div
            class="grid grid-cols-[180px_1fr] gap-4 border-b border-border-faint py-3"
          >
            <dt class="font-sans text-[13px] text-fg-subtle">{{ row.term }}</dt>
            <dd class="m-0 font-sans text-[13px] text-fg">{{ row.desc }}</dd>
          </div>
        }
      }
    </dl>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DescriptionListComponent {
  readonly rows = input.required<readonly DescriptionRow[]>();
  readonly inline = input(false);

  protected readonly listClasses = computed(() =>
    this.inline()
      ? 'm-0 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2'
      : 'm-0',
  );
}
