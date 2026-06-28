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
        <h2 class="ed-rn-label">Read next</h2>
        @for (article of relatedArticles(); track article.slug) {
          <a [routerLink]="routeFor(article)" class="ed-rn-row">
            <span class="ed-rn-meta">
              <span
                class="ed-dot"
                [style.background]="
                  'var(--dot-' + article.type + ', var(--fg-faint))'
                "
                aria-hidden="true"
              ></span>
              <span class="sr-only">{{ article.type }} — </span>
              <span aria-hidden="true">{{ article.type }}</span>
            </span>
            <h3 class="ed-rn-title">{{ article.title }}</h3>
            @if (article.excerpt) {
              <p class="ed-rn-excerpt">{{ article.excerpt }}</p>
            }
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
