import {
  Component,
  ChangeDetectionStrategy,
  inject,
  input,
  computed,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, BookOpen, ChevronRight } from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';

@Component({
  selector: 'app-article-series-nav',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    @if (seriesArticles().length > 1) {
    <nav
      class="rounded-sm border border-zinc-800 bg-zinc-900/50 p-5"
      aria-label="系列文章導覽"
    >
      <div class="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-300">
        <lucide-icon [img]="BookOpenIcon" [size]="16" />
        系列文章
      </div>
      <ol class="space-y-1.5">
        @for (article of seriesArticles(); track article.id; let i = $index) {
        <li>
          @if (article.id === currentArticleId()) {
          <span
            class="flex items-center gap-2 rounded-sm bg-zinc-800 px-3 py-2 text-sm font-medium text-zinc-100"
          >
            <span class="shrink-0 text-xs text-zinc-500">{{ i + 1 }}.</span>
            {{ article.title }}
          </span>
          } @else {
          <a
            [routerLink]="'/articles/' + article.id"
            class="flex items-center gap-2 rounded-sm px-3 py-2 text-sm text-zinc-400 no-underline transition-colors hover:bg-zinc-800/50 hover:text-zinc-200"
          >
            <span class="shrink-0 text-xs text-zinc-600">{{ i + 1 }}.</span>
            {{ article.title }}
            <lucide-icon
              [img]="ChevronRightIcon"
              [size]="12"
              class="ml-auto shrink-0 text-zinc-600"
            />
          </a>
          }
        </li>
        }
      </ol>
    </nav>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticleSeriesNavComponent {
  private readonly articleService = inject(ArticleService);

  readonly seriesId = input.required<string>();
  readonly currentArticleId = input.required<string>();

  protected readonly BookOpenIcon = BookOpen;
  protected readonly ChevronRightIcon = ChevronRight;

  protected readonly seriesArticles = computed(() =>
    this.articleService.getArticlesBySeries(this.seriesId()),
  );
}
