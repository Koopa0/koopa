import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';

/**
 * DS sidebar nav row — `ui-navitem`. Renders as an `<a>` when `href` is set,
 * otherwise a `<button>`. Active row gets the brand-faint surface and a
 * brand-tinted icon; an optional trailing `count` sits right-aligned in mono.
 * Project the leading icon into `[nav-icon]`.
 */
@Component({
  selector: 'app-nav-item',
  imports: [NgTemplateOutlet],
  template: `
    @if (href()) {
      <a
        [href]="href()"
        [attr.aria-current]="active() ? 'page' : null"
        [attr.data-testid]="testId()"
        [class]="classes()"
      >
        <ng-container [ngTemplateOutlet]="content" />
      </a>
    } @else {
      <button
        type="button"
        [attr.aria-current]="active() ? 'page' : null"
        [attr.data-testid]="testId()"
        [class]="classes()"
      >
        <ng-container [ngTemplateOutlet]="content" />
      </button>
    }

    <ng-template #content>
      <span
        class="inline-flex shrink-0 [&_svg]:size-4"
        [class.text-brand]="active()"
        aria-hidden="true"
      >
        <ng-content select="[nav-icon]" />
      </span>
      <span class="truncate">{{ label() }}</span>
      @if (count() !== undefined && count() !== null) {
        <span class="ml-auto font-mono text-[11px] text-fg-faint">
          {{ count() }}
        </span>
      }
    </ng-template>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NavItemComponent {
  readonly label = input.required<string>();
  readonly active = input(false);
  readonly count = input<number | null>(null);
  readonly href = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() =>
    [
      'flex w-full items-center gap-2.5 rounded-sm px-2.5 py-[7px]',
      'cursor-pointer border-0 bg-transparent text-left no-underline',
      'font-sans text-[13px] leading-normal',
      'transition-colors duration-[120ms]',
      this.active()
        ? 'bg-brand-faint text-fg'
        : 'text-fg-muted hover:bg-overlay hover:text-fg',
    ].join(' '),
  );
}
