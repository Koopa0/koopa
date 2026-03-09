import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  DestroyRef,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowRight,
  Clock,
  FileText,
  Hammer,
  Lightbulb,
} from 'lucide-angular';
import { ContentService } from '../../../core/services/content.service';
import type { ApiContent, ContentType } from '../../../core/models';

interface FeedEntry {
  id: string;
  title: string;
  excerpt: string;
  path: string;
  publishedAt: Date;
  type: 'article' | 'build-log' | 'til';
  tags: string[];
}

const FEED_LIMIT = 6;

/** 從 API 回傳的 ContentType 對應到 FeedEntry type */
const FEED_TYPE_MAP: Partial<Record<ContentType, FeedEntry['type']>> = {
  article: 'article',
  'build-log': 'build-log',
  til: 'til',
};

/** 從 FeedEntry type 對應到路由前綴 */
const PATH_PREFIX_MAP: Record<FeedEntry['type'], string> = {
  article: '/articles',
  'build-log': '/build-logs',
  til: '/til',
};

@Component({
  selector: 'app-latest-feed',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  template: `
    <section class="border-b border-zinc-800 bg-zinc-950">
      <div class="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8">
        <div class="mb-12 flex items-center justify-between">
          <div>
            <h2 class="text-3xl font-bold text-zinc-100">Latest</h2>
            <p class="mt-3 text-zinc-400">最新的文章、開發紀錄與學習筆記</p>
          </div>
          <a
            routerLink="/articles"
            class="hidden items-center gap-1.5 text-sm font-medium text-zinc-400 no-underline transition-colors hover:text-zinc-200 sm:inline-flex"
          >
            View All
            <lucide-icon [img]="ArrowRightIcon" [size]="14" />
          </a>
        </div>

        <div class="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          @for (entry of feedEntries(); track entry.id) {
            <a
              [routerLink]="entry.path"
              class="group rounded-sm border border-zinc-800 bg-zinc-900/50 p-6 no-underline transition-all duration-200 hover:-translate-y-1 hover:border-zinc-600 hover:shadow-lg hover:shadow-zinc-950/50"
            >
              <div class="mb-3 flex items-center gap-2">
                <span
                  class="flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-xs font-medium"
                  [class]="getTypeClass(entry.type)"
                >
                  <lucide-icon [img]="getTypeIcon(entry.type)" [size]="10" />
                  {{ getTypeLabel(entry.type) }}
                </span>
                @for (tag of entry.tags.slice(0, 2); track tag) {
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
                {{ entry.title }}
              </h3>
              <p
                class="mb-4 line-clamp-2 text-sm leading-relaxed text-zinc-400"
              >
                {{ entry.excerpt }}
              </p>
              <div class="text-xs text-zinc-500">
                {{ entry.publishedAt | date: 'yyyy/MM/dd' }}
              </div>
            </a>
          }
        </div>

        <div class="mt-8 text-center sm:hidden">
          <a
            routerLink="/articles"
            class="inline-flex items-center gap-1.5 text-sm font-medium text-zinc-400 no-underline transition-colors hover:text-zinc-200"
          >
            View All
            <lucide-icon [img]="ArrowRightIcon" [size]="14" />
          </a>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LatestFeedComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly FileTextIcon = FileText;
  protected readonly HammerIcon = Hammer;
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly ClockIcon = Clock;

  private readonly allContent = signal<ApiContent[]>([]);

  protected readonly feedEntries = computed<FeedEntry[]>(() => {
    return this.allContent()
      .filter((item) => item.type in FEED_TYPE_MAP && item.published_at != null)
      .map((item) => {
        const feedType = FEED_TYPE_MAP[item.type]!;
        return {
          id: `${feedType}-${item.id}`,
          title: item.title,
          excerpt: item.excerpt || item.body.slice(0, 120),
          path: `${PATH_PREFIX_MAP[feedType]}/${item.slug}`,
          publishedAt: new Date(item.published_at!),
          type: feedType,
          tags: item.tags,
        };
      })
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime())
      .slice(0, FEED_LIMIT);
  });

  ngOnInit(): void {
    this.contentService
      .listPublished({ perPage: FEED_LIMIT * 3 })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((response) => {
        this.allContent.set(response.data);
      });
  }

  protected getTypeLabel(type: FeedEntry['type']): string {
    const labels: Record<FeedEntry['type'], string> = {
      article: 'Article',
      'build-log': 'Build Log',
      til: 'TIL',
    };
    return labels[type];
  }

  protected getTypeClass(type: FeedEntry['type']): string {
    const classes: Record<FeedEntry['type'], string> = {
      article: 'bg-sky-900/50 text-sky-400',
      'build-log': 'bg-amber-900/50 text-amber-400',
      til: 'bg-emerald-900/50 text-emerald-400',
    };
    return classes[type];
  }

  protected getTypeIcon(type: FeedEntry['type']): typeof FileText {
    const icons: Record<FeedEntry['type'], typeof FileText> = {
      article: this.FileTextIcon,
      'build-log': this.HammerIcon,
      til: this.LightbulbIcon,
    };
    return icons[type];
  }
}
