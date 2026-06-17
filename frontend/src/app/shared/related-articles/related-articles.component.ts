import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import type { ApiRelatedContent } from '../../core/models';
import { contentTypeRoute } from '../../core/models';

const MAX_READ_NEXT = 2;

/** "Read next" — up to two related pieces as quiet editorial rows. */
@Component({
  selector: 'app-related-articles',
  imports: [RouterLink],
  template: `
    @if (relatedArticles().length > 0) {
      <section aria-label="Read next">
        <h2
          class="mb-1 font-mono text-[11px] uppercase tracking-[0.08em] text-fg-faint"
        >
          Read next
        </h2>
        @for (article of relatedArticles(); track article.slug) {
          <a
            [routerLink]="routeFor(article)"
            class="group block border-border-faint py-[18px] no-underline [&:not(:first-of-type)]:border-t"
          >
            <div
              class="mb-[7px] flex items-center gap-[9px] font-mono text-[11px] text-fg-subtle"
            >
              <span
                class="size-[7px] rounded-full"
                [style.background]="
                  'var(--dot-' + article.type + ', var(--fg-faint))'
                "
                aria-hidden="true"
              ></span>
              <span class="tracking-[0.03em]">{{ article.type }}</span>
            </div>
            <h3
              class="font-display text-[17px] font-semibold leading-snug text-fg transition-colors duration-(--dur-base) group-hover:text-brand"
            >
              {{ article.title }}
            </h3>
            <p
              class="mt-1 line-clamp-2 font-serif text-[14.5px] leading-relaxed text-fg-muted"
            >
              {{ article.excerpt }}
            </p>
          </a>
        }
      </section>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RelatedArticlesComponent {
  readonly articles = input<ApiRelatedContent[]>([]);

  protected readonly relatedArticles = computed(() =>
    this.articles().slice(0, MAX_READ_NEXT),
  );

  protected routeFor(article: ApiRelatedContent): string {
    return `${contentTypeRoute(article.type)}/${article.slug}`;
  }
}
