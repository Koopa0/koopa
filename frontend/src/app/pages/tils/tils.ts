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
import {
  LucideAngularModule,
  Calendar,
  Lightbulb,
  Tag,
} from 'lucide-angular';
import { TilService } from '../../core/services/til.service';
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
  private readonly tilService = inject(TilService);
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
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly TagIcon = Tag;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Today I Learned',
      description: 'Daily learning notes — bite-sized technical discoveries.',
      ogUrl: 'https://koopa0.dev/til',
      jsonLd: buildCollectionPageSchema({
        name: 'Today I Learned',
        description: 'Daily learning notes — bite-sized technical discoveries.',
        url: 'https://koopa0.dev/til',
      }),
    });
    this.loadTils();
  }

  protected selectTag(tag: string | null): void {
    this.selectedTag.set(tag);
  }

  private loadTils(): void {
    this.tilService.getTils(1, 100).subscribe({
      next: (response) => {
        this.tils.set(response.tils);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load TIL entries');
        this.isLoading.set(false);
      },
    });
  }
}
