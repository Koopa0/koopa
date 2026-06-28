import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  computed,
  inject,
  input,
  linkedSignal,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { rxResource } from '@angular/core/rxjs-interop';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type {
  ApiContent,
  ApiListResponse,
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

interface YearGroup {
  year: string;
  items: ApiContent[];
}

/**
 * The reading index — served at both `/` and `/articles`. One editorial
 * list consolidating every written content type (article / essay /
 * build-log / til / digest); the `type` query param narrows by type
 * (the per-type lists are folded into this one index).
 */
@Component({
  selector: 'app-articles',
  imports: [DatePipe, RouterLink],
  templateUrl: './articles.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticlesComponent implements OnInit {
  /** Query param: /articles?type=essay narrows the index to one type. */
  readonly type = input<string>();

  private readonly contentService = inject(ContentService);
  private readonly seoService = inject(SeoService);
  private readonly router = inject(Router);

  /** The canonical content types, exposed for the type filter row. */
  protected readonly contentTypes = CONTENT_TYPES;

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

  protected readonly contents = computed(() =>
    this.contentsResource.hasValue() ? this.contentsResource.value().data : [],
  );

  /**
   * contents() grouped by published year, newest year first; undated
   * pieces sink into a trailing "—" bucket. Pure derivation — no query change.
   * Page-scoped: server pagination is perPage:50, so the per-year counts
   * reflect the current page, not corpus totals. Honest at the current corpus;
   * once a single year exceeds one page, the counts should come from a server
   * aggregate (flag, don't build).
   */
  protected readonly grouped = computed<YearGroup[]>(() => {
    const byYear = new Map<string, ApiContent[]>();
    for (const c of this.contents()) {
      const year = c.published_at
        ? new Date(c.published_at).getUTCFullYear().toString()
        : '—';
      const bucket = byYear.get(year);
      if (bucket) {
        bucket.push(c);
      } else {
        byYear.set(year, [c]);
      }
    }
    return [...byYear.entries()]
      .map(([year, items]) => ({ year, items }))
      .sort((a, b) =>
        a.year === '—'
          ? 1
          : b.year === '—'
            ? -1
            : Number(b.year) - Number(a.year),
      );
  });

  protected readonly isLoading = computed(
    () => this.contentsResource.status() === 'loading',
  );

  protected readonly loadError = computed(
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
      title: 'Articles',
      description,
      ogUrl: `${environment.siteUrl}/articles`,
      canonicalUrl: `${environment.siteUrl}/articles`,
      jsonLd: buildCollectionPageSchema({
        name: 'Articles',
        description,
        url: `${environment.siteUrl}/articles`,
      }),
    });
  }

  protected setType(type?: ContentType): void {
    void this.router.navigate(['/articles'], {
      queryParams: type ? { type } : {},
    });
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
}
