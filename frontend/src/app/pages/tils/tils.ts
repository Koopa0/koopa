import {
  Component,
  ChangeDetectionStrategy,
  inject,
  computed,
  signal,
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
import { fadeInUp } from '../../shared/animations/fade-in.animation';

@Component({
  selector: 'app-tils',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './tils.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class TilsComponent {
  private readonly tilService = inject(TilService);
  private readonly seoService = inject(SeoService);

  protected readonly tils = this.tilService.publishedTils;
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

  constructor() {
    this.seoService.updateMeta({
      title: 'Today I Learned',
      description: '每日學習紀錄 — 短小精悍的技術筆記和發現',
      ogUrl: 'https://koopa0.dev/til',
    });
  }

  protected selectTag(tag: string | null): void {
    this.selectedTag.set(tag);
  }
}
