import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  computed,
} from '@angular/core';

type PageToken = number | 'gap';

/**
 * DS pagination — `ui-page`. Prev/next + a computed numbered window with `…`
 * gaps. `page` is a 1-based two-way model. The current page is marked with
 * `aria-current=page` and a brand-muted chip (text-brand-strong for AA).
 */
@Component({
  selector: 'app-pagination',
  template: `
    <nav
      [attr.aria-label]="ariaLabel()"
      [attr.data-testid]="testId()"
      class="flex items-center gap-1"
    >
      <button
        type="button"
        [disabled]="page() <= 1 || null"
        [attr.aria-disabled]="page() <= 1 || null"
        [attr.aria-label]="prevLabel()"
        data-testid="pagination-prev"
        class="inline-flex h-[30px] min-w-[30px] cursor-pointer items-center justify-center rounded-sm px-2 font-mono text-xs text-fg-muted transition-colors duration-[120ms] hover:bg-overlay hover:text-fg disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-35"
        (click)="go(page() - 1)"
      >
        ‹
      </button>

      @for (token of tokens(); track $index) {
        @if (token === 'gap') {
          <span
            class="inline-flex h-[30px] min-w-[30px] items-center justify-center font-mono text-xs text-fg-faint select-none"
            aria-hidden="true"
          >
            …
          </span>
        } @else {
          <button
            type="button"
            [attr.aria-current]="token === page() ? 'page' : null"
            [attr.aria-label]="'Page ' + token"
            [attr.data-testid]="'pagination-page-' + token"
            class="inline-flex h-[30px] min-w-[30px] cursor-pointer items-center justify-center rounded-sm px-2 font-mono text-xs text-fg-muted transition-colors duration-[120ms] hover:bg-overlay hover:text-fg aria-[current=page]:bg-brand-muted aria-[current=page]:text-brand-strong aria-[current=page]:hover:bg-brand-muted aria-[current=page]:hover:text-brand-strong"
            (click)="go(token)"
          >
            {{ token }}
          </button>
        }
      }

      <button
        type="button"
        [disabled]="page() >= pageCount() || null"
        [attr.aria-disabled]="page() >= pageCount() || null"
        [attr.aria-label]="nextLabel()"
        data-testid="pagination-next"
        class="inline-flex h-[30px] min-w-[30px] cursor-pointer items-center justify-center rounded-sm px-2 font-mono text-xs text-fg-muted transition-colors duration-[120ms] hover:bg-overlay hover:text-fg disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-35"
        (click)="go(page() + 1)"
      >
        ›
      </button>
    </nav>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PaginationComponent {
  readonly total = input.required<number>();
  readonly pageSize = input<number>(10);
  readonly page = model.required<number>();
  /** Number of sibling pages to show on each side of the current page. */
  readonly siblings = input<number>(1);
  readonly ariaLabel = input<string>('Pagination');
  readonly prevLabel = input<string>('Previous page');
  readonly nextLabel = input<string>('Next page');
  readonly testId = input<string | null>(null);

  protected readonly pageCount = computed(() =>
    Math.max(1, Math.ceil(this.total() / Math.max(1, this.pageSize()))),
  );

  protected readonly tokens = computed<readonly PageToken[]>(() => {
    const count = this.pageCount();
    const current = Math.min(Math.max(1, this.page()), count);
    const sib = Math.max(0, this.siblings());

    // boundary (1) + boundary (last) + current + 2*siblings + 2 gaps
    const slots = sib * 2 + 5;
    if (count <= slots) {
      return Array.from({ length: count }, (_, i) => i + 1);
    }

    const left = Math.max(current - sib, 2);
    const right = Math.min(current + sib, count - 1);
    const showLeftGap = left > 2;
    const showRightGap = right < count - 1;

    const result: PageToken[] = [1];
    if (showLeftGap) {
      result.push('gap');
    } else {
      for (let p = 2; p < left; p++) {
        result.push(p);
      }
    }
    for (let p = left; p <= right; p++) {
      result.push(p);
    }
    if (showRightGap) {
      result.push('gap');
    } else {
      for (let p = right + 1; p < count; p++) {
        result.push(p);
      }
    }
    result.push(count);
    return result;
  });

  protected go(target: number): void {
    const clamped = Math.min(Math.max(1, target), this.pageCount());
    if (clamped !== this.page()) {
      this.page.set(clamped);
    }
  }
}
