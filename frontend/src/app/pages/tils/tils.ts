import {
  Component,
  ChangeDetectionStrategy,
  inject,
  computed,
  signal,
  OnInit,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { LucideAngularModule, Calendar, Tag } from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-tils',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './tils.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class TilsComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly seoService = inject(SeoService);

  protected readonly tils = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly selectedTag = signal<string | null>(null);

  protected readonly allTags = computed(() => {
    const tagSet = new Set<string>();
    for (const til of this.tils()) {
      for (const tag of til.tags) {
        tagSet.add(tag);
      }
    }
    return Array.from(tagSet).sort();
  });

  protected readonly filteredTils = computed(() => {
    const tag = this.selectedTag();
    if (!tag) {
      return this.tils();
    }
    return this.tils().filter((t) => t.tags.includes(tag));
  });

  protected readonly CalendarIcon = Calendar;
  protected readonly TagIcon = Tag;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Today I Learned',
      description: 'Daily learning notes — bite-sized technical discoveries.',
      ogUrl: `${environment.siteUrl}/til`,
      jsonLd: buildCollectionPageSchema({
        name: 'Today I Learned',
        description: 'Daily learning notes — bite-sized technical discoveries.',
        url: `${environment.siteUrl}/til`,
      }),
    });
    this.loadTils();
  }

  protected selectTag(tag: string | null): void {
    this.selectedTag.set(tag);
  }

  private loadTils(): void {
    this.contentService.listByType('til', { page: 1, perPage: 100 }).subscribe({
      next: (response) => {
        this.tils.set(response.data);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load TIL entries');
        this.isLoading.set(false);
      },
    });
  }
}
