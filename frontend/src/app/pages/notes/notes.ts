import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Calendar,
  StickyNote,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-notes',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './notes.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NotesComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly notes = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly CalendarIcon = Calendar;
  protected readonly StickyNoteIcon = StickyNote;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Notes',
      description: 'Code snippets, config notes, and reading notes.',
      ogUrl: `${environment.siteUrl}/notes`,
      jsonLd: buildCollectionPageSchema({
        name: 'Notes',
        description: 'Code snippets, config notes, and reading notes.',
        url: `${environment.siteUrl}/notes`,
      }),
    });
    this.loadNotes();
  }

  protected loadNotes(): void {
    this.contentService.listByType('note', { page: 1, perPage: 100 }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (response) => {
        this.notes.set(response.data);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load notes');
        this.isLoading.set(false);
      },
    });
  }
}
