import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  computed,
  linkedSignal,
  input,
  OnInit,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser, DatePipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { environment } from '../../../environments/environment';
import { TopicService } from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type {
  ApiTopic,
  ApiContent,
  ApiPaginationMeta,
  ContentType,
} from '../../core/models';

/** Per-type tally for the topic head meta line. */
interface TypeCount {
  type: ContentType;
  count: number;
}

const CONTENTS_PER_PAGE = 12;
const CONTENT_TYPES: readonly ContentType[] = [
  'article',
  'essay',
  'build-log',
  'til',
  'digest',
];

/**
 * The topic page — a restrained header (topic name, one-line description,
 * and a mono meta line carrying the piece count plus a dot per type
 * present), then the type filter and the same left-biased date-spine
 * timeline as the reading index.
 */
@Component({
  selector: 'app-topic-detail',
  imports: [RouterLink, DatePipe],
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
  protected readonly meta = signal<ApiPaginationMeta | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly isNotFound = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly currentPage = signal(1);

  /** Selected type tab — snaps back to "all" whenever new contents load. */
  protected readonly selectedType = linkedSignal<
    ApiContent[],
    'all' | ContentType
  >({
    source: () => this.contents(),
    computation: () => 'all',
  });

  /** Distinct content types present on the current page, in canonical order. */
  protected readonly typesPresent = computed(() => {
    const present = new Set(this.contents().map((c) => c.type));
    return CONTENT_TYPES.filter((type) => present.has(type));
  });

  /** Per-type tallies for the head meta line, in canonical order. */
  protected readonly typeCounts = computed<TypeCount[]>(() => {
    const all = this.contents();
    return CONTENT_TYPES.map((type) => ({
      type,
      count: all.filter((c) => c.type === type).length,
    })).filter((entry) => entry.count > 0);
  });

  protected readonly filteredContents = computed(() => {
    const type = this.selectedType();
    const all = this.contents();
    return type === 'all' ? all : all.filter((c) => c.type === type);
  });

  protected readonly totalPages = computed(() => this.meta()?.total_pages ?? 0);

  ngOnInit(): void {
    this.loadTopicContents(this.slug(), 1);
  }

  protected selectType(type: 'all' | ContentType): void {
    this.selectedType.set(type);
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
          this.meta.set(result.meta);
          this.isLoading.set(false);

          const url = `${environment.siteUrl}/topics/${slug}`;
          const description =
            result.topic.description ||
            `Browse all content under the "${result.topic.name}" topic.`;
          this.seoService.updateMeta({
            title: result.topic.name,
            description,
            ogUrl: url,
            canonicalUrl: url,
            jsonLd: buildCollectionPageSchema({
              name: result.topic.name,
              description,
              url,
            }),
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
