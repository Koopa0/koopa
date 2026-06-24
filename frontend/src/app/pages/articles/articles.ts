import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  computed,
  inject,
  input,
  linkedSignal,
} from '@angular/core';
import { Router } from '@angular/router';
import { rxResource } from '@angular/core/rxjs-interop';
import { LucideAngularModule, FileText, X } from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { TopicService } from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import { PostRowComponent } from '../../shared/post-row/post-row.component';
import { SkeletonComponent } from '../../shared/skeleton/skeleton.component';
import type {
  ApiContent,
  ApiListResponse,
  ApiTopic,
  ContentType,
} from '../../core/models';

const PER_PAGE = 50;
const CONTENT_TYPES: readonly ContentType[] = [
  'article',
  'essay',
  'build-log',
  'til',
  'digest',
];

interface ContentsQuery {
  type?: ContentType;
  page: number;
}

/**
 * The reading index — served at both `/` and `/articles`. One editorial
 * list consolidating every written content type (article / essay /
 * build-log / til / digest); the `type` query param narrows by type
 * (retired /essays, /til, /build-logs lists redirect here) and the topic
 * chips narrow client-side by topic.
 */
@Component({
  selector: 'app-articles',
  imports: [LucideAngularModule, PostRowComponent, SkeletonComponent],
  templateUrl: './articles.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticlesComponent implements OnInit {
  /** Query param: /articles?type=essay narrows the index to one type. */
  readonly type = input<string>();

  private readonly contentService = inject(ContentService);
  private readonly topicService = inject(TopicService);
  private readonly seoService = inject(SeoService);
  private readonly router = inject(Router);

  protected readonly FileTextIcon = FileText;
  protected readonly XIcon = X;

  protected readonly typeFilter = computed<ContentType | undefined>(() => {
    const requested = this.type();
    return CONTENT_TYPES.includes(requested as ContentType)
      ? (requested as ContentType)
      : undefined;
  });

  /** Current page — snaps back to 1 whenever the type filter changes. */
  protected readonly page = linkedSignal<ContentType | undefined, number>({
    source: () => this.typeFilter(),
    computation: () => 1,
  });

  /** Selected topic chip — snaps back to "all" when the type changes. */
  protected readonly topicFilter = linkedSignal<ContentType | undefined, string>(
    {
      source: () => this.typeFilter(),
      computation: () => 'all',
    },
  );

  protected readonly contentsResource = rxResource<
    ApiListResponse<ApiContent>,
    ContentsQuery
  >({
    params: () => ({ type: this.typeFilter(), page: this.page() }),
    stream: ({ params }) =>
      this.contentService.listPublished({
        type: params.type,
        page: params.page,
        perPage: PER_PAGE,
      }),
  });

  protected readonly topicsResource = rxResource<ApiTopic[], void>({
    stream: () => this.topicService.getAllTopics(),
  });

  protected readonly contents = computed(() =>
    this.contentsResource.hasValue() ? this.contentsResource.value().data : [],
  );

  // Only surface topics that actually have published content — the public
  // /api/topics returns every seeded topic (content_count is published-only),
  // so without this the index shows a wall of empty, dead filter chips.
  protected readonly topics = computed(() => {
    const all = this.topicsResource.hasValue()
      ? this.topicsResource.value()
      : [];
    return all.filter((t) => t.content_count > 0);
  });

  protected readonly filteredContents = computed(() => {
    const topic = this.topicFilter();
    const items = this.contents();
    if (topic === 'all') {
      return items;
    }
    return items.filter((c) => c.topics.some((t) => t.slug === topic));
  });

  protected readonly isLoading = computed(
    () => this.contentsResource.status() === 'loading',
  );

  protected readonly hasError = computed(
    () => this.contentsResource.status() === 'error',
  );

  protected readonly totalPages = computed(() =>
    this.contentsResource.hasValue()
      ? this.contentsResource.value().meta.total_pages
      : 0,
  );

  ngOnInit(): void {
    const description =
      'Every written piece — articles, essays, build logs, TILs, and digests.';

    this.seoService.updateMeta({
      title: 'Article',
      description,
      ogUrl: `${environment.siteUrl}/articles`,
      canonicalUrl: `${environment.siteUrl}/articles`,
      jsonLd: buildCollectionPageSchema({
        name: 'Article',
        description,
        url: `${environment.siteUrl}/articles`,
      }),
    });
  }

  protected selectTopic(slug: string): void {
    this.topicFilter.set(slug);
  }

  protected clearTypeFilter(): void {
    this.router.navigate(['/articles']);
  }

  protected previousPage(): void {
    if (this.page() > 1) {
      this.page.update((p) => p - 1);
    }
  }

  protected nextPage(): void {
    if (this.page() < this.totalPages()) {
      this.page.update((p) => p + 1);
    }
  }

  protected retry(): void {
    this.contentsResource.reload();
  }
}
