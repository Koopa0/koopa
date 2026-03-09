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
  Tag,
} from 'lucide-angular';
import { TilService } from '../../core/services/til.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { TilEntry } from '../../core/models';

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
  private readonly route = inject(ActivatedRoute);
  private readonly location = inject(Location);
  private readonly tilService = inject(TilService);
  private readonly markdownService = inject(MarkdownService);
  private readonly sanitizer = inject(DomSanitizer);
  private readonly seoService = inject(SeoService);

  protected readonly til = signal<TilEntry | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  // SECURITY_REVIEW: 內容由 MarkdownService 產生，非使用者可注入
  protected readonly parsedContent = computed<SafeHtml>(() => {
    const t = this.til();
    if (!t) {
      return '';
    }
    const html = this.markdownService.parse(t.content);
    return this.sanitizer.bypassSecurityTrustHtml(html);
  });

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly TagIcon = Tag;

  ngOnInit(): void {
    const slug = this.route.snapshot.paramMap.get('slug');
    if (slug) {
      this.loadTil(slug);
    } else {
      this.error.set('TIL 不存在');
      this.isLoading.set(false);
    }
  }

  private loadTil(slug: string): void {
    this.tilService.getBySlug(slug).subscribe({
      next: (til) => {
        this.til.set(til);
        this.isLoading.set(false);
        this.seoService.updateMeta({
          title: til.title,
          description: til.content.slice(0, 160),
          ogUrl: `https://koopa0.dev/til/${til.slug}`,
          ogType: 'article',
        });
      },
      error: () => {
        this.error.set('載入 TIL 失敗');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }
}
