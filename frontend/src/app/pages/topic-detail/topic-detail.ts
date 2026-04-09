import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  computed,
  input,
  OnInit,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Calendar,
  Clock,
  ChevronLeft,
  ChevronRight,
  Layers,
  Tag,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import {
  TopicService,
  type RelatedTag,
} from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { CONTENT_TYPE_CONFIG, contentTypeRoute } from '../../core/models';
import type {
  ApiTopic,
  ApiContent,
  ApiPaginationMeta,
} from '../../core/models';

const CONTENTS_PER_PAGE = 12;

@Component({
  selector: 'app-topic-detail',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './topic-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TopicDetailComponent implements OnInit {
  /** Route param: topics/:slug */
  readonly slug = input.required<string>();

  private readonly topicService = inject(TopicService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly platformId = inject(PLATFORM_ID);

  protected readonly topic = signal<ApiTopic | null>(null);
  protected readonly contents = signal<ApiContent[]>([]);
  protected readonly relatedTags = signal<RelatedTag[]>([]);
  protected readonly selectedTag = signal<string | null>(null);
  protected readonly meta = signal<ApiPaginationMeta | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly isNotFound = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly currentPage = signal(1);

  protected readonly filteredContents = computed(() => {
    const tag = this.selectedTag();
    const all = this.contents();
    return tag ? all.filter((c) => c.tags.includes(tag)) : all;
  });

  protected readonly totalPages = computed(() => this.meta()?.total_pages ?? 1);
  protected readonly pageArray = computed(() =>
    Array.from({ length: this.totalPages() }, (_, i) => i + 1),
  );

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly LayersIcon = Layers;
  protected readonly TagIcon = Tag;

  protected readonly contentTypeConfig = CONTENT_TYPE_CONFIG;

  ngOnInit(): void {
    this.loadTopicContents(this.slug(), 1);
  }

  protected getBadgeClasses(content: ApiContent): string {
    return (
      this.contentTypeConfig[content.type]?.badgeClasses ??
      'bg-zinc-800 text-zinc-400'
    );
  }

  protected getTypeLabel(content: ApiContent): string {
    return this.contentTypeConfig[content.type]?.labelZh ?? content.type;
  }

  protected getContentRoute(content: ApiContent): string {
    return `${contentTypeRoute(content.type)}/${content.slug}`;
  }

  protected toggleTag(tag: string): void {
    if (!tag) {
      this.selectedTag.set(null);
    } else {
      this.selectedTag.update((current) => (current === tag ? null : tag));
    }
  }

  protected onPageChange(page: number): void {
    this.currentPage.set(page);
    this.loadTopicContents(this.slug(), page);
    if (isPlatformBrowser(this.platformId)) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  private loadTopicContents(slug: string, page: number): void {
    this.isLoading.set(true);
    this.error.set(null);

    this.topicService
      .getTopicBySlug(slug, { page, perPage: CONTENTS_PER_PAGE })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result) => {
          this.topic.set(result.topic);
          this.contents.set(result.contents);
          this.relatedTags.set(result.related_tags);
          this.meta.set(result.meta);
          this.isLoading.set(false);

          this.seoService.updateMeta({
            title: result.topic.name,
            description:
              result.topic.description ||
              `Browse all content under the "${result.topic.name}" topic.`,
            ogUrl: `${environment.siteUrl}/topics/${slug}`,
          });
        },
        error: (err) => {
          if (err?.status === 404) {
            this.isNotFound.set(true);
          } else {
            this.error.set(
              'Failed to load topic content. Please try again later.',
            );
          }
          this.isLoading.set(false);
        },
      });
  }
}
