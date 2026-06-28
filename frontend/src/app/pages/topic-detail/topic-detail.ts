import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  effect,
  linkedSignal,
  input,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser, DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { rxResource } from '@angular/core/rxjs-interop';
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

interface TopicContentsResult {
  topic: ApiTopic;
  contents: ApiContent[];
  meta: ApiPaginationMeta;
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
export class TopicDetailComponent {
  /** Route param: topics/:slug */
  readonly slug = input.required<string>();

  private readonly topicService = inject(TopicService);
  private readonly seoService = inject(SeoService);
  private readonly platformId = inject(PLATFORM_ID);

  /** Current page — set by the pager; drives a resource refetch. */
  protected readonly currentPage = signal(1);

  private readonly topicResource = rxResource<
    TopicContentsResult,
    { slug: string; page: number }
  >({
    params: () => ({ slug: this.slug(), page: this.currentPage() }),
    stream: ({ params }) =>
      this.topicService.getTopicBySlug(params.slug, {
        page: params.page,
        perPage: CONTENTS_PER_PAGE,
      }),
  });

  // Guarded reads — a bare value() throws on a failed load and kills the error
  // UI (project gotcha: "rxResource value() throws — guard it").
  protected readonly topic = computed(() =>
    this.topicResource.hasValue() ? this.topicResource.value().topic : null,
  );
  protected readonly contents = computed(() =>
    this.topicResource.hasValue() ? this.topicResource.value().contents : [],
  );
  protected readonly meta = computed(() =>
    this.topicResource.hasValue() ? this.topicResource.value().meta : null,
  );

  protected readonly isLoading = computed(
    () => this.topicResource.status() === 'loading',
  );
  protected readonly isNotFound = computed(
    () => httpStatus(this.topicResource.error()) === 404,
  );
  protected readonly error = computed(() =>
    this.topicResource.status() === 'error' && !this.isNotFound()
      ? 'Failed to load topic content. Please try again later.'
      : null,
  );

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

  constructor() {
    // SEO is dynamic (depends on the loaded topic), so update it as a side
    // effect when the resource resolves. Runs on both server and browser, so
    // the SSR render emits the topic-specific title / OG / JSON-LD.
    effect(() => {
      const topic = this.topic();
      if (!topic) {
        return;
      }
      const url = `${environment.siteUrl}/topics/${this.slug()}`;
      const description =
        topic.description ||
        `Browse all content under the "${topic.name}" topic.`;
      this.seoService.updateMeta({
        title: topic.name,
        description,
        ogUrl: url,
        canonicalUrl: url,
        jsonLd: buildCollectionPageSchema({
          name: topic.name,
          description,
          url,
        }),
      });
    });
  }

  protected selectType(type: 'all' | ContentType): void {
    this.selectedType.set(type);
  }

  protected onPageChange(page: number): void {
    this.currentPage.set(page);
    if (isPlatformBrowser(this.platformId)) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }
}

function httpStatus(err: unknown): number | null {
  return err instanceof HttpErrorResponse ? err.status : null;
}
