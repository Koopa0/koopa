import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Calendar,
  Clock,
  Eye,
  Tag,
  FileText,
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { SkeletonComponent } from '../../shared/skeleton/skeleton.component';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { SeoService } from '../../core/services/seo/seo.service';
import { ArticleListItem } from '../../core/models';

@Component({
  selector: 'app-tag',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule, SkeletonComponent],
  templateUrl: './tag.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class TagComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly articleService = inject(ArticleService);
  private readonly seoService = inject(SeoService);

  protected readonly tagName = signal('');
  protected readonly articles = signal<ArticleListItem[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly EyeIcon = Eye;
  protected readonly TagIcon = Tag;
  protected readonly FileTextIcon = FileText;

  ngOnInit(): void {
    const tag = this.route.snapshot.paramMap.get('tag');
    if (tag) {
      this.tagName.set(tag);
      this.loadArticles(tag);

      this.seoService.updateMeta({
        title: `${tag} 相關文章`,
        description: `所有標記為 ${tag} 的技術文章`,
        ogUrl: `https://koopa0.dev/tags/${tag}`,
      });
    }
  }

  private loadArticles(tag: string): void {
    this.isLoading.set(true);

    this.articleService
      .getArticles({
        tags: [tag],
        sortBy: 'publishedAt',
        sortOrder: 'desc',
        limit: 100,
      })
      .subscribe({
        next: (response) => {
          this.articles.set(response.articles);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('載入文章失敗，請稍後再試');
          this.isLoading.set(false);
        },
      });
  }
}
