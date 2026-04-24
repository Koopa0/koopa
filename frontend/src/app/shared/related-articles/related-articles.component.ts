import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, Clock } from 'lucide-angular';
import type { ApiRelatedContent } from '../../core/models';
import { contentTypeRoute } from '../../core/models';

@Component({
  selector: 'app-related-articles',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    @if (relatedArticles().length > 0) {
    <section class="border-t border-zinc-800 pt-8">
      <h2 class="mb-6 text-xl font-bold text-zinc-100">Related Articles</h2>
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
        @for (article of relatedArticles(); track article.slug) {
        <a
          [routerLink]="routeFor(article)"
          class="group rounded-sm border border-zinc-800 bg-zinc-900/50 p-4 no-underline transition-all hover:border-zinc-600 hover:bg-zinc-900"
        >
          <h3
            class="mb-2 text-sm font-semibold text-zinc-200 group-hover:text-white"
          >
            {{ article.title }}
          </h3>
          <p class="mb-3 line-clamp-2 text-xs leading-relaxed text-zinc-500">
            {{ article.excerpt }}
          </p>
        </a>
        }
      </div>
    </section>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RelatedArticlesComponent {
  readonly articles = input<ApiRelatedContent[]>([]);

  protected readonly ClockIcon = Clock;

  protected readonly relatedArticles = computed(() => this.articles());

  protected routeFor(article: ApiRelatedContent): string {
    return `${contentTypeRoute(article.type)}/${article.slug}`;
  }
}
