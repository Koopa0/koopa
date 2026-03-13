import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  input,
  computed,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { Location, DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Calendar,
  Tag,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-til-detail',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './til-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class TilDetailComponent implements OnInit {
  /** Route param: til/:slug */
  readonly slug = input.required<string>();

  private readonly location = inject(Location);
  private readonly contentService = inject(ContentService);
  private readonly markdownService = inject(MarkdownService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly til = signal<ApiContent | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  /** Sanitized HTML — MarkdownService uses DOMPurify, safe for [innerHTML] */
  protected readonly parsedContent = computed(() => {
    const t = this.til();
    if (!t) {
      return '';
    }
    const body = t.body.replace(/^#\s+.+\n+/, '');
    return this.markdownService.parse(body);
  });

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly TagIcon = Tag;

  ngOnInit(): void {
    this.loadTil(this.slug());
  }

  private loadTil(slug: string): void {
    this.contentService.getBySlug(slug).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (til) => {
        this.til.set(til);
        this.isLoading.set(false);
        this.seoService.updateMeta({
          title: til.title,
          description: til.excerpt || til.body.slice(0, 160),
          ogUrl: `${environment.siteUrl}/til/${til.slug}`,
          ogType: 'article',
        });
      },
      error: () => {
        this.error.set('Failed to load TIL entry');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }
}
