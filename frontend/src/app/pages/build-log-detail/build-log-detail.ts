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
  Hammer,
  Tag,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { SeoService } from '../../core/services/seo/seo.service';
import type { ApiContent } from '../../core/models';

interface BuildLogMeta {
  project: string | null;
  sessionType: string | null;
  tags: string[];
}

@Component({
  selector: 'app-build-log-detail',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './build-log-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
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

  /** Extract metadata (project, session_type, tags) from body frontmatter */
  protected readonly meta = computed<BuildLogMeta>(() => {
    const bl = this.buildLog();
    if (!bl) {
      return { project: null, sessionType: null, tags: [] };
    }
    const body = bl.body;
    const projectMatch = body.match(/^project:\s*(.+)$/m);
    const sessionMatch = body.match(/^session_type:\s*(.+)$/m);
    const tagsMatch = body.match(/^tags:\s*\[([^\]]*)\]/m);
    const tags = tagsMatch
      ? tagsMatch[1]
          .split(',')
          .map((t) => t.trim().replace(/^["']|["']$/g, ''))
          .filter(Boolean)
      : bl.tags ?? [];
    return {
      project: projectMatch ? projectMatch[1].trim() : null,
      sessionType: sessionMatch ? sessionMatch[1].trim() : null,
      tags,
    };
  });

  /** Parse body: strip frontmatter header, render markdown */
  protected readonly parsedContent = computed(() => {
    const bl = this.buildLog();
    if (!bl) {
      return '';
    }
    // Strip leading h1
    let body = bl.body.replace(/^#\s+.+\n+/, '');
    // Strip YAML-like frontmatter lines before the first ## heading
    body = body
      .replace(/^(?:project|session_type|title|tags|body):\s*.*\n*/gm, '')
      .trimStart();
    return this.markdownService.parse(body);
  });

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly HammerIcon = Hammer;
  protected readonly TagIcon = Tag;

  /** Session type display labels */
  protected readonly sessionTypeLabels: Record<string, string> = {
    feature: '功能開發',
    bugfix: 'Bug 修復',
    refactor: '重構',
    devops: 'DevOps',
    research: '研究',
  };

  ngOnInit(): void {
    this.loadBuildLog(this.slug());
  }

  private loadBuildLog(slug: string): void {
    this.contentService
      .getBySlug(slug)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
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
