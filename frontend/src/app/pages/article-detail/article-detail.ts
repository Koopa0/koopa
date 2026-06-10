import {
  Component,
  DestroyRef,
  inject,
  signal,
  input,
  ChangeDetectionStrategy,
  OnInit,
  computed,
  PLATFORM_ID,
  ElementRef,
  afterNextRender,
  effect,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { isPlatformBrowser } from '@angular/common';
import { Location, DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, ArrowLeft, AlertCircle } from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ArticleService } from '../../core/services/article.service';
import { ContentService } from '../../core/services/content.service';
import { MarkdownService } from '../../core/services/markdown.service';
import type { ApiContent, ApiRelatedContent } from '../../core/models';
import { contentTypeLabelEn } from '../../core/models';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildBlogPostingSchema } from '../../core/services/seo/json-ld.util';
import { TableOfContentsComponent } from '../../shared/table-of-contents/table-of-contents.component';
import { RelatedArticlesComponent } from '../../shared/related-articles/related-articles.component';

/**
 * The reading surface — renders every written content type (article /
 * essay / build-log / til / digest) fetched by slug. Has two homes:
 * /articles/:slug (full chrome: breadcrumbs, TOC, read next) and
 * /preview/:slug (chrome-less column for the admin publish-preview
 * iframe, noindex).
 */
@Component({
  selector: 'app-article-detail',
  standalone: true,
  imports: [
    DatePipe,
    RouterLink,
    LucideAngularModule,
    TableOfContentsComponent,
    RelatedArticlesComponent,
  ],
  templateUrl: './article-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticleDetailComponent implements OnInit {
  /** Route param: articles/:slug or preview/:slug */
  readonly slug = input.required<string>();

  /** Route data flag: /preview/:slug renders the bare reading column. */
  readonly preview = input(false);

  private readonly location = inject(Location);
  private readonly articleService = inject(ArticleService);
  private readonly contentService = inject(ContentService);
  private readonly markdownService = inject(MarkdownService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly el = inject(ElementRef);

  protected readonly article = signal<ApiContent | null>(null);
  protected readonly relatedArticles = signal<ApiRelatedContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly rawHtml = computed(() => {
    const article = this.article();
    if (!article) {
      return '';
    }
    // Strip leading h1 from markdown — the title is already rendered in the header section
    const body = article.body.replace(/^#\s+.+\n+/, '');
    return this.markdownService.parse(body);
  });

  /** Sanitized HTML — MarkdownService uses DOMPurify, safe for [innerHTML] */
  protected readonly parsedContent = this.rawHtml;

  /** Human label for the breadcrumb tail (e.g. "Build Log"). */
  protected readonly typeLabel = computed(() => {
    const article = this.article();
    return article ? contentTypeLabelEn(article.type) : '';
  });

  /** First attached topic drives the breadcrumb topic link. */
  protected readonly primaryTopic = computed(
    () => this.article()?.topics[0] ?? null,
  );

  /**
   * Layout wrapper: full mode centers a reading column with the
   * "On this page" rail; preview mode is a bare, left-aligned column.
   */
  protected readonly wrapperClass = computed(() =>
    this.preview()
      ? 'max-w-[760px] px-6 pt-8 pb-16 sm:px-10'
      : 'mx-auto max-w-6xl px-6 pt-11 pb-28 sm:px-10 lg:grid lg:grid-cols-[minmax(0,680px)_192px] lg:justify-center lg:gap-14',
  );

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly AlertCircleIcon = AlertCircle;

  private isBrowser = false;

  constructor() {
    afterNextRender(() => {
      this.isBrowser = true;
    });

    // Inject copy buttons into <pre> blocks when content changes
    effect(() => {
      this.parsedContent(); // track dependency
      if (!this.isBrowser || !isPlatformBrowser(this.platformId)) return;
      // Wait for DOM update
      setTimeout(() => this.injectCopyButtons(), 0);
    });
  }

  ngOnInit(): void {
    this.loadArticle(this.slug());
  }

  protected loadArticle(slug: string): void {
    this.isLoading.set(true);
    this.error.set(null);

    this.articleService
      .getArticleBySlug(slug)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (article) => {
          this.article.set(article);
          this.isLoading.set(false);
          this.updateSeo(article);
          if (!this.preview()) {
            this.loadRelated(article.slug);
          }
        },
        error: () => {
          this.error.set('Failed to load article');
          this.isLoading.set(false);
        },
      });
  }

  private loadRelated(slug: string): void {
    this.contentService
      .getRelated(slug)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (related) => this.relatedArticles.set(related),
        error: () => {
          // graceful degradation — hide related section on error
        },
      });
  }

  protected goBack(): void {
    this.location.back();
  }

  private updateSeo(article: ApiContent): void {
    if (this.preview()) {
      // The preview iframe must never be indexed or carry canonical/JSON-LD.
      this.seoService.updateMeta({
        title: article.title,
        description: article.excerpt,
        noIndex: true,
      });
      return;
    }

    const articleUrl = `${environment.siteUrl}/articles/${article.slug}`;
    this.seoService.updateMeta({
      title: article.title,
      description: article.excerpt,
      ogTitle: article.title,
      ogDescription: article.excerpt,
      ogImage: article.cover_image ?? undefined,
      ogUrl: articleUrl,
      ogType: 'article',
      twitterCard: 'summary_large_image',
      canonicalUrl: articleUrl,
      jsonLd: buildBlogPostingSchema({
        title: article.title,
        description: article.excerpt,
        url: articleUrl,
        publishedAt: article.published_at ?? article.created_at,
        updatedAt: article.updated_at,
        coverImage: article.cover_image ?? undefined,
        tags: article.tags,
      }),
    });
  }

  private injectCopyButtons(): void {
    const root = this.el.nativeElement as HTMLElement;
    const preBlocks = root.querySelectorAll('.prose pre');

    for (const pre of Array.from(preBlocks)) {
      if (pre.querySelector('.copy-btn')) continue;

      const wrapper = document.createElement('div');
      wrapper.style.position = 'relative';
      pre.parentNode?.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);

      const btn = document.createElement('button');
      btn.className =
        'copy-btn absolute right-2 top-2 rounded-xs border border-border bg-elevated px-2 py-1 text-xs text-fg-subtle opacity-0 transition-opacity hover:text-fg group-hover:opacity-100';
      btn.textContent = 'Copy';
      btn.type = 'button';
      wrapper.classList.add('group');
      wrapper.appendChild(btn);

      btn.addEventListener('click', () => {
        const code =
          pre.querySelector('code')?.textContent ?? pre.textContent ?? '';
        navigator.clipboard.writeText(code).then(() => {
          btn.textContent = 'Copied!';
          setTimeout(() => {
            btn.textContent = 'Copy';
          }, 1500);
        });
      });
    }
  }
}
