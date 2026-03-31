import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Calendar,
  Bookmark,
  ExternalLink,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-bookmarks',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './bookmarks.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BookmarksComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly bookmarks = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly CalendarIcon = Calendar;
  protected readonly BookmarkIcon = Bookmark;
  protected readonly ExternalLinkIcon = ExternalLink;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Bookmarks',
      description: 'Curated resources with personal commentary.',
      ogUrl: `${environment.siteUrl}/bookmarks`,
      jsonLd: buildCollectionPageSchema({
        name: 'Bookmarks',
        description: 'Curated resources with personal commentary.',
        url: `${environment.siteUrl}/bookmarks`,
      }),
    });
    this.loadBookmarks();
  }

  protected loadBookmarks(): void {
    this.contentService
      .listByType('bookmark', { page: 1, perPage: 50 })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.bookmarks.set(response.data);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('Failed to load bookmarks');
          this.isLoading.set(false);
        },
      });
  }
}
