import { Component, ChangeDetectionStrategy, input } from '@angular/core';

export interface BreadcrumbItem {
  readonly label: string;
  readonly href?: string;
}

/**
 * DS breadcrumbs — `ui-crumbs`. Mono 11px trail with `/` separators. Links are
 * fg-subtle→fg on hover; the last item is the current page (fg-muted,
 * `aria-current=page`) and never a link.
 */
@Component({
  selector: 'app-breadcrumbs',
  template: `
    <nav
      [attr.aria-label]="ariaLabel()"
      [attr.data-testid]="testId()"
      class="flex flex-wrap items-center gap-2 font-mono text-[11px] text-fg-subtle"
    >
      @for (item of items(); track $index; let last = $last) {
        @if (last) {
          <span
            class="text-fg-muted"
            aria-current="page"
            [attr.data-testid]="'crumb-' + $index"
          >
            {{ item.label }}
          </span>
        } @else {
          @if (item.href) {
            <a
              [href]="item.href"
              class="text-fg-subtle no-underline transition-colors duration-[120ms] hover:text-fg"
              [attr.data-testid]="'crumb-' + $index"
            >
              {{ item.label }}
            </a>
          } @else {
            <span [attr.data-testid]="'crumb-' + $index">{{ item.label }}</span>
          }
          <span class="text-fg-subtle" aria-hidden="true">/</span>
        }
      }
    </nav>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BreadcrumbsComponent {
  readonly items = input.required<readonly BreadcrumbItem[]>();
  readonly ariaLabel = input<string>('Breadcrumb');
  readonly testId = input<string | null>(null);
}
