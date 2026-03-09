import {
  Component,
  inject,
  signal,
  ChangeDetectionStrategy,
  OnInit,
  computed,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { Location, DatePipe } from '@angular/common';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import {
  LucideAngularModule,
  ArrowLeft,
  Share2,
  Calendar,
  Clock,
  AlertCircle,
  Copy,
  Check,
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { MarkdownService } from '../../core/services/markdown.service';
import type { ApiContent } from '../../core/models';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildBlogPostingSchema } from '../../core/services/seo/json-ld.util';
import { TableOfContentsComponent } from '../../shared/table-of-contents/table-of-contents.component';
import { ArticleSeriesNavComponent } from '../../shared/article-series-nav/article-series-nav.component';
import { RelatedArticlesComponent } from '../../shared/related-articles/related-articles.component';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

@Component({
  selector: 'app-article-detail',
  standalone: true,
  imports: [
    DatePipe,
    LucideAngularModule,
    TableOfContentsComponent,
    ArticleSeriesNavComponent,
    RelatedArticlesComponent,
  ],
  templateUrl: './article-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class ArticleDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly location = inject(Location);
  private readonly articleService = inject(ArticleService);
  private readonly markdownService = inject(MarkdownService);
  private readonly sanitizer = inject(DomSanitizer);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);

  protected readonly article = signal<ApiContent | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly isCopied = signal(false);

  protected readonly rawHtml = computed(() => {
    const article = this.article();
    if (!article) {
      return '';
    }
    return this.markdownService.parse(article.body);
  });

  // SECURITY_REVIEW: bypassSecurityTrustHtml 用於渲染 markdown 產生的 HTML。
  // 安全性由 MarkdownService 保證：marked 解析 + highlight.js 語法高亮，
  // 不包含使用者可注入的 raw HTML。若未來接受使用者輸入的 markdown，
  // 必須在 MarkdownService 加入 DOMPurify 等 sanitizer。
  protected readonly parsedContent = computed<SafeHtml>(() => {
    const html = this.rawHtml();
    if (!html) {
      return '';
    }
    return this.sanitizer.bypassSecurityTrustHtml(html);
  });

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly Share2Icon = Share2;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly AlertCircleIcon = AlertCircle;
  protected readonly CopyIcon = Copy;
  protected readonly CheckIcon = Check;

  ngOnInit(): void {
    const slug = this.route.snapshot.paramMap.get('id');
    if (slug) {
      this.loadArticle(slug);
    } else {
      this.error.set('文章 ID 不存在');
      this.isLoading.set(false);
    }
  }

  protected loadArticle(slug: string): void {
    this.isLoading.set(true);
    this.error.set(null);

    this.articleService.getArticleBySlug(slug).subscribe({
      next: (article) => {
        this.article.set(article);
        this.isLoading.set(false);
        this.updateSeo(article);
      },
      error: () => {
        this.error.set('載入文章失敗');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }

  private updateSeo(article: ApiContent): void {
    const articleUrl = `https://koopa0.dev/articles/${article.slug}`;
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

  protected shareArticle(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    const article = this.article();
    if (!article) {
      return;
    }

    if (navigator.share) {
      navigator.share({
        title: article.title,
        text: article.excerpt,
        url: window.location.href,
      });
    } else {
      navigator.clipboard.writeText(window.location.href).then(() => {
        this.isCopied.set(true);
        setTimeout(() => this.isCopied.set(false), 2000);
      });
    }
  }
}
