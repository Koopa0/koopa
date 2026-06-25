import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, ChevronRight } from 'lucide-angular';
import type { ApiContent } from '../../core/models';

/**
 * One editorial article card — the shared reading-index item used by the
 * front door, the articles index, and search results. A soft surface lifts
 * on hover; meta line (type dot · type · date · reading time), display
 * title, serif excerpt. Every content type links to the single reading
 * surface at /articles/:slug.
 *
 * `cta` opts into a "Read article" affordance — used on the front door's
 * featured cards; the dense reading index leaves it off to stay scannable.
 */
@Component({
  selector: 'app-post-row',
  imports: [RouterLink, DatePipe, LucideAngularModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <a
      [routerLink]="'/articles/' + content().slug"
      class="group -mx-4 block rounded-xl px-4 py-5 no-underline transition-colors duration-(--dur-base) hover:bg-panel"
      data-testid="index-row"
    >
      <div class="mb-[7px] flex items-center gap-[9px] font-mono text-[11px]">
        <span
          class="size-[7px] rounded-full"
          [style.background]="
            'var(--dot-' + content().type + ', var(--fg-faint))'
          "
          aria-hidden="true"
        ></span>
        <span class="tracking-[0.03em] text-fg-subtle">{{
          content().type
        }}</span>
        @if (content().published_at) {
          <span class="text-fg-faint" aria-hidden="true">·</span>
          <span class="text-fg-faint">{{
            content().published_at | date: 'MMM d, yyyy' : 'UTC'
          }}</span>
        }
        <span class="ml-auto text-fg-faint"
          >{{ content().reading_time_min }} min</span
        >
      </div>
      <h2
        class="font-serif text-[21px] font-medium leading-[1.3] tracking-[-0.005em] text-fg transition-colors duration-(--dur-base) group-hover:text-brand"
      >
        {{ content().title }}
      </h2>
      @if (content().excerpt) {
        <p
          class="mt-[7px] max-w-[640px] font-serif text-[15.5px] leading-[1.65] text-fg-muted"
        >
          {{ content().excerpt }}
        </p>
      }
      @if (cta()) {
        <span
          class="mt-3 inline-flex items-center gap-1 text-[13px] font-medium text-brand"
          aria-hidden="true"
          data-testid="index-row-cta"
        >
          Read article
          <lucide-icon
            class="transition-transform duration-(--dur-base) group-hover:translate-x-0.5"
            [img]="ChevronRightIcon"
            [size]="15"
            [strokeWidth]="1.8"
          />
        </span>
      }
    </a>
  `,
})
export class PostRowComponent {
  readonly content = input.required<ApiContent>();

  /** Show the "Read article" affordance (front-door featured cards). */
  readonly cta = input(false);

  protected readonly ChevronRightIcon = ChevronRight;
}
