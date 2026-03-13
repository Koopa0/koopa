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
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { isPlatformBrowser } from '@angular/common';
import { Location, DatePipe } from '@angular/common';
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
import { environment } from '../../../environments/environment';
import { ArticleService } from '../../core/services/article.service';
import { MarkdownService } from '../../core/services/markdown.service';
import type { ApiContent } from '../../core/models';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildBlogPostingSchema } from '../../core/services/seo/json-ld.util';
import { TableOfContentsComponent } from '../../shared/table-of-contents/table-of-contents.component';
import { RelatedArticlesComponent } from '../../shared/related-articles/related-articles.component';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

@Component({
  selector: 'app-article-detail',
  standalone: true,
  imports: [
    DatePipe,
    LucideAngularModule,
    TableOfContentsComponent,
    RelatedArticlesComponent,
  ],
  templateUrl: './article-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class ArticleDetailComponent implements OnInit {
  /** Route param: articles/:id */
  readonly id = input.required<string>();

  private readonly location = inject(Location);
  private readonly articleService = inject(ArticleService);
  private readonly markdownService = inject(MarkdownService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly article = signal<ApiContent | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly isCopied = signal(false);

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

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly Share2Icon = Share2;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly AlertCircleIcon = AlertCircle;
  protected readonly CopyIcon = Copy;
  protected readonly CheckIcon = Check;

  ngOnInit(): void {
    this.loadArticle(this.id());
  }

  protected loadArticle(slug: string): void {
    this.isLoading.set(true);
    this.error.set(null);

    this.articleService.getArticleBySlug(slug).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (article) => {
        this.article.set(article);
        this.isLoading.set(false);
        this.updateSeo(article);
      },
      error: () => {
        this.error.set('Failed to load article');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }

  private updateSeo(article: ApiContent): void {
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
