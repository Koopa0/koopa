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
import { Location, DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Calendar,
  Clock,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import type { ApiContent } from '../../core/models';
import { TableOfContentsComponent } from '../../shared/table-of-contents/table-of-contents.component';

@Component({
  selector: 'app-build-log-detail',
  standalone: true,
  imports: [DatePipe, LucideAngularModule, TableOfContentsComponent],
  templateUrl: './build-log-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class BuildLogDetailComponent implements OnInit {
  /** Route param: build-logs/:slug */
  readonly slug = input.required<string>();

  private readonly location = inject(Location);
  private readonly contentService = inject(ContentService);
  private readonly markdownService = inject(MarkdownService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly buildLog = signal<ApiContent | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly rawHtml = computed(() => {
    const bl = this.buildLog();
    if (!bl) {
      return '';
    }
    // Strip leading h1 — title is already in the header section
    const body = bl.body.replace(/^#\s+.+\n+/, '');
    return this.markdownService.parse(body);
  });

  /** Sanitized HTML — MarkdownService uses DOMPurify, safe for [innerHTML] */
  protected readonly parsedContent = this.rawHtml;

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;

  ngOnInit(): void {
    this.loadBuildLog(this.slug());
  }

  private loadBuildLog(slug: string): void {
    this.contentService.getBySlug(slug).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (bl) => {
        this.buildLog.set(bl);
        this.isLoading.set(false);
        this.seoService.updateMeta({
          title: bl.title,
          description: bl.excerpt,
          ogUrl: `${environment.siteUrl}/build-logs/${bl.slug}`,
          ogType: 'article',
        });
      },
      error: () => {
        this.error.set('Failed to load build log');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }
}
