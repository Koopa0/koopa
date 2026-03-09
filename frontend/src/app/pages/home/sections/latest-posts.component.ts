import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  DestroyRef,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { LucideAngularModule, ArrowRight, Clock } from 'lucide-angular';
import { ContentService } from '../../../core/services/content.service';
import type { ApiContent } from '../../../core/models';

const LATEST_POSTS_LIMIT = 6;

@Component({
  selector: 'app-latest-posts',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  template: `
    <section class="border-b border-zinc-800 bg-zinc-950">
      <div class="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8">
        <div class="mb-12 flex items-center justify-between">
          <div>
            <h2 class="text-3xl font-bold text-zinc-100">
              Latest from the Blog
            </h2>
            <p class="mt-3 text-zinc-400">Technical articles, dev notes, and lessons learned</p>
          </div>
          <a
            routerLink="/articles"
            class="hidden items-center gap-1.5 text-sm font-medium text-zinc-400 no-underline transition-colors hover:text-zinc-200 sm:inline-flex"
          >
            View All Articles
            <lucide-icon [img]="ArrowRightIcon" [size]="14" />
          </a>
        </div>

        <div class="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          @for (article of latestArticles(); track article.id) {
            <a
              [routerLink]="'/articles/' + article.slug"
              class="group rounded-sm border border-zinc-800 bg-zinc-900/50 p-6 no-underline transition-all duration-200 hover:-translate-y-1 hover:border-zinc-600 hover:shadow-lg hover:shadow-zinc-950/50"
            >
              <div class="mb-3 flex flex-wrap gap-2">
                @for (tag of article.tags.slice(0, 2); track tag) {
                  <span
                    class="rounded-sm bg-zinc-800 px-2 py-0.5 text-xs text-zinc-500"
                  >
                    {{ tag }}
                  </span>
                }
              </div>
              <h3
                class="mb-3 text-lg font-semibold text-zinc-100 group-hover:text-white"
              >
                {{ article.title }}
              </h3>
              <p
                class="mb-4 line-clamp-2 text-sm leading-relaxed text-zinc-400"
              >
                {{ article.excerpt }}
              </p>
              <div class="flex items-center gap-4 text-xs text-zinc-500">
                <span>{{
                  article.published_at | date: 'yyyy/MM/dd'
                }}</span>
                <span class="flex items-center gap-1">
                  <lucide-icon [img]="ClockIcon" [size]="12" />
                  {{ article.reading_time }} min
                </span>
              </div>
            </a>
          }
        </div>

        <div class="mt-8 text-center sm:hidden">
          <a
            routerLink="/articles"
            class="inline-flex items-center gap-1.5 text-sm font-medium text-zinc-400 no-underline transition-colors hover:text-zinc-200"
          >
            View All Articles
            <lucide-icon [img]="ArrowRightIcon" [size]="14" />
          </a>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LatestPostsComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly latestArticles = signal<ApiContent[]>([]);

  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly ClockIcon = Clock;

  ngOnInit(): void {
    this.contentService
      .listByType('article', { perPage: LATEST_POSTS_LIMIT })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((response) => {
        this.latestArticles.set(response.data);
      });
  }
}
