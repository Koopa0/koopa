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
  Tag,
  FileText,
} from 'lucide-angular';
import { TagService } from '../../core/services/tag.service';
import { SkeletonComponent } from '../../shared/skeleton/skeleton.component';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { SeoService } from '../../core/services/seo/seo.service';
import type { ApiContent } from '../../core/models';

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
  private readonly tagService = inject(TagService);
  private readonly seoService = inject(SeoService);

  protected readonly tagName = signal('');
  protected readonly contents = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly TagIcon = Tag;
  protected readonly FileTextIcon = FileText;

  ngOnInit(): void {
    const tag = this.route.snapshot.paramMap.get('tag');
    if (tag) {
      this.tagName.set(tag);
      this.loadContents(tag);

      this.seoService.updateMeta({
        title: `Tag: ${tag}`,
        description: `All content tagged with ${tag}`,
        ogUrl: `https://koopa0.dev/tags/${tag}`,
      });
    }
  }

  private loadContents(tag: string): void {
    this.isLoading.set(true);

    this.tagService.getContentsByTag(tag, 1, 100).subscribe({
      next: (response) => {
        this.contents.set(response.contents);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load content. Please try again later.');
        this.isLoading.set(false);
      },
    });
  }
}
