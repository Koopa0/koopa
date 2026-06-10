import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import type { ApiContent } from '../../core/models';

/**
 * One editorial list row — the shared reading-index row used by the
 * articles index, topic pages, and search results. Meta line (type dot ·
 * type · date · reading time), display title, serif excerpt. Every
 * content type links to the single reading surface at /articles/:slug.
 */
@Component({
  selector: 'app-post-row',
  standalone: true,
  imports: [RouterLink, DatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <a
      [routerLink]="'/articles/' + content().slug"
      class="group block py-[22px] no-underline"
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
            content().published_at | date: 'MMM d, yyyy'
          }}</span>
        }
        <span class="ml-auto text-fg-faint"
          >{{ content().reading_time_min }} min</span
        >
      </div>
      <h2
        class="font-display text-[21px] font-semibold leading-[1.25] tracking-[-0.015em] text-fg transition-colors duration-(--dur-base) group-hover:text-brand"
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
    </a>
  `,
})
export class PostRowComponent {
  readonly content = input.required<ApiContent>();
}
