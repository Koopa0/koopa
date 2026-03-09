import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
} from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Location, DatePipe } from '@angular/common';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import {
  LucideAngularModule,
  ArrowLeft,
  Calendar,
  Clock,
  FolderOpen,
} from 'lucide-angular';
import { BuildLogService } from '../../core/services/build-log.service';
import { ProjectService } from '../../core/services/project/project.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { BuildLog } from '../../core/models';
import { TableOfContentsComponent } from '../../shared/table-of-contents/table-of-contents.component';

@Component({
  selector: 'app-build-log-detail',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule, TableOfContentsComponent],
  templateUrl: './build-log-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class BuildLogDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly location = inject(Location);
  private readonly buildLogService = inject(BuildLogService);
  private readonly projectService = inject(ProjectService);
  private readonly markdownService = inject(MarkdownService);
  private readonly sanitizer = inject(DomSanitizer);
  private readonly seoService = inject(SeoService);

  protected readonly buildLog = signal<BuildLog | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly rawHtml = computed(() => {
    const bl = this.buildLog();
    if (!bl) {
      return '';
    }
    return this.markdownService.parse(bl.content);
  });

  // SECURITY_REVIEW: 同 article-detail — 內容由 MarkdownService 產生，非使用者可注入
  protected readonly parsedContent = computed<SafeHtml>(() => {
    const html = this.rawHtml();
    return html ? this.sanitizer.bypassSecurityTrustHtml(html) : '';
  });

  protected readonly projectTitle = computed(() => {
    const bl = this.buildLog();
    if (!bl) {
      return '';
    }
    return this.projectService.getProjectById(bl.projectId)?.title ?? '';
  });

  protected readonly projectSlug = computed(() => {
    const bl = this.buildLog();
    if (!bl) {
      return '';
    }
    return this.projectService.getProjectById(bl.projectId)?.slug ?? '';
  });

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly FolderOpenIcon = FolderOpen;

  ngOnInit(): void {
    const slug = this.route.snapshot.paramMap.get('slug');
    if (slug) {
      this.loadBuildLog(slug);
    } else {
      this.error.set('Build log 不存在');
      this.isLoading.set(false);
    }
  }

  private loadBuildLog(slug: string): void {
    this.buildLogService.getBySlug(slug).subscribe({
      next: (bl) => {
        this.buildLog.set(bl);
        this.isLoading.set(false);
        this.seoService.updateMeta({
          title: bl.title,
          description: bl.excerpt,
          ogUrl: `https://koopa0.dev/build-logs/${bl.slug}`,
          ogType: 'article',
        });
      },
      error: () => {
        this.error.set('載入開發日誌失敗');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }
}
