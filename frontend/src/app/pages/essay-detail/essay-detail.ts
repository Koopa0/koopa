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
import { ContentService } from '../../core/services/content.service';
import { MarkdownService } from '../../core/services/markdown.service';
import type { ApiContent } from '../../core/models';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildBlogPostingSchema } from '../../core/services/seo/json-ld.util';
import { TableOfContentsComponent } from '../../shared/table-of-contents/table-of-contents.component';
import { RelatedArticlesComponent } from '../../shared/related-articles/related-articles.component';

@Component({
  selector: 'app-essay-detail',
  standalone: true,
  imports: [
    DatePipe,
    LucideAngularModule,
    TableOfContentsComponent,
    RelatedArticlesComponent,
  ],
  templateUrl: './essay-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EssayDetailComponent implements OnInit {
  /** Route param: essays/:id */
  readonly id = input.required<string>();

  private readonly location = inject(Location);
  private readonly contentService = inject(ContentService);
  private readonly markdownService = inject(MarkdownService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly el = inject(ElementRef);

  protected readonly essay = signal<ApiContent | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly isCopied = signal(false);

  protected readonly rawHtml = computed(() => {
    const essay = this.essay();
    if (!essay) {
      return '';
    }
    // Strip leading h1 from markdown — the title is already rendered in the header section
    const body = essay.body.replace(/^#\s+.+\n+/, '');
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
    this.loadEssay(this.id());
  }

  protected loadEssay(slug: string): void {
    this.isLoading.set(true);
    this.error.set(null);

    this.contentService
      .getBySlug(slug)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (essay) => {
          this.essay.set(essay);
          this.isLoading.set(false);
          this.updateSeo(essay);
        },
        error: () => {
          this.error.set('Failed to load essay');
          this.isLoading.set(false);
        },
      });
  }

  protected goBack(): void {
    this.location.back();
  }

  private updateSeo(essay: ApiContent): void {
    const essayUrl = `${environment.siteUrl}/essays/${essay.slug}`;
    this.seoService.updateMeta({
      title: essay.title,
      description: essay.excerpt,
      ogTitle: essay.title,
      ogDescription: essay.excerpt,
      ogImage: essay.cover_image ?? undefined,
      ogUrl: essayUrl,
      ogType: 'article',
      twitterCard: 'summary_large_image',
      canonicalUrl: essayUrl,
      jsonLd: buildBlogPostingSchema({
        title: essay.title,
        description: essay.excerpt,
        url: essayUrl,
        publishedAt: essay.published_at ?? essay.created_at,
        updatedAt: essay.updated_at,
        coverImage: essay.cover_image ?? undefined,
        tags: essay.tags,
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
        'copy-btn absolute right-2 top-2 rounded-xs border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-400 opacity-0 transition-opacity hover:text-zinc-200 group-hover:opacity-100';
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

  protected shareEssay(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    const essay = this.essay();
    if (!essay) {
      return;
    }

    if (navigator.share) {
      navigator.share({
        title: essay.title,
        text: essay.excerpt,
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
