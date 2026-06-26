import {
  Component,
  ChangeDetectionStrategy,
  computed,
  inject,
  input,
  PLATFORM_ID,
  ElementRef,
  afterNextRender,
  effect,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { of } from 'rxjs';
import { isPlatformBrowser, DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { ThemeService } from '../../core/services/theme.service';
import type { ApiContent, ApiRelatedContent } from '../../core/models';
import { contentTypeLabelEn } from '../../core/models';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildBlogPostingSchema } from '../../core/services/seo/json-ld.util';
import { TableOfContentsComponent } from '../../shared/table-of-contents/table-of-contents.component';
import { RelatedArticlesComponent } from '../../shared/related-articles/related-articles.component';

/**
 * The reading surface — renders every written content type (article /
 * essay / build-log / til / digest). The article is resolved by
 * {@link articleResolver} before the route activates (so the page-level view
 * transition lands on the finished page, never a spinner) and arrives via the
 * `article` input. Has two homes: /articles/:slug (full chrome: breadcrumbs,
 * TOC, read next) and /preview/:slug (chrome-less column for the admin
 * publish-preview iframe, noindex).
 */
@Component({
  selector: 'app-article-detail',
  imports: [
    DatePipe,
    RouterLink,
    TableOfContentsComponent,
    RelatedArticlesComponent,
  ],
  templateUrl: './article-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticleDetailComponent {
  /** The resolved article — bound from the route's resolve key via
   * withComponentInputBinding, so it is always present at first render. */
  readonly article = input.required<ApiContent>();

  /** Route data flag: /preview/:slug renders the bare reading column. */
  readonly preview = input(false);

  private readonly contentService = inject(ContentService);
  private readonly markdownService = inject(MarkdownService);
  private readonly themeService = inject(ThemeService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);
  private readonly el = inject(ElementRef);

  /** Related pieces — non-critical, below the fold. A `undefined` param keeps
   * the resource idle in preview mode (no request). */
  private readonly relatedResource = rxResource<
    ApiRelatedContent[],
    string | undefined
  >({
    params: () => (this.preview() ? undefined : this.article().slug),
    stream: ({ params }) =>
      params
        ? this.contentService.getRelated(params)
        : of<ApiRelatedContent[]>([]),
  });

  protected readonly relatedArticles = computed(() =>
    this.relatedResource.hasValue() ? this.relatedResource.value() : [],
  );

  protected readonly rawHtml = computed(() => {
    // Strip leading h1 from markdown — the title is already rendered in the header section
    const body = this.article().body.replace(/^#\s+.+\n+/, '');
    return this.markdownService.parse(body);
  });

  /** Sanitized HTML — MarkdownService uses DOMPurify, safe for [innerHTML] */
  protected readonly parsedContent = this.rawHtml;

  /** Human label for the breadcrumb tail (e.g. "Build Log"). */
  protected readonly typeLabel = computed(() =>
    contentTypeLabelEn(this.article().type),
  );

  /** First attached topic drives the breadcrumb topic link. */
  protected readonly primaryTopic = computed(
    () => this.article().topics[0] ?? null,
  );

  private isBrowser = false;

  constructor() {
    afterNextRender(() => {
      this.isBrowser = true;
    });

    // Keep SEO meta in sync with the resolved article. An effect (not ngOnInit)
    // so it re-runs on article→article navigation, where the router reuses this
    // component instance and only the `article` input changes.
    effect(() => this.updateSeo(this.article()));

    // Inject copy buttons into <pre> blocks when content changes
    effect(() => {
      this.parsedContent(); // track dependency
      if (!this.isBrowser || !isPlatformBrowser(this.platformId)) return;
      // Wait for DOM update
      setTimeout(() => this.injectCopyButtons(), 0);
    });

    // Render mermaid diagrams (lazy-loads mermaid only when one is present).
    // Tracks the theme so a light/dark toggle re-renders in the matching palette.
    effect(() => {
      this.parsedContent(); // track content
      const isDark = this.themeService.isDarkMode(); // track theme
      if (!this.isBrowser || !isPlatformBrowser(this.platformId)) return;
      setTimeout(() => {
        void this.markdownService.renderMermaid(
          this.el.nativeElement as HTMLElement,
          isDark,
        );
      }, 0);
    });
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
      }),
    });
  }

  private injectCopyButtons(): void {
    const root = this.el.nativeElement as HTMLElement;
    const preBlocks = root.querySelectorAll('.ed-prose pre');

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
