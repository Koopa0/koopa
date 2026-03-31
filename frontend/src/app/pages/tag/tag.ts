import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  input,
  OnInit,
} from '@angular/core';
import { RouterLink } from '@angular/router';
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
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-tag',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule, SkeletonComponent],
  templateUrl: './tag.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TagComponent implements OnInit {
  /** Route param: tags/:tag */
  readonly tag = input.required<string>();

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
    const tagValue = this.tag();
    this.tagName.set(tagValue);
    this.loadContents(tagValue);

    this.seoService.updateMeta({
      title: `Tag: ${tagValue}`,
      description: `All content tagged with ${tagValue}`,
      ogUrl: `${environment.siteUrl}/tags/${tagValue}`,
    });
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
