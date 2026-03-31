import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  input,
  computed,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { Location, DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Calendar,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { SeoService } from '../../core/services/seo/seo.service';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-note-detail',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './note-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NoteDetailComponent implements OnInit {
  /** Route param: notes/:slug */
  readonly slug = input.required<string>();

  private readonly location = inject(Location);
  private readonly contentService = inject(ContentService);
  private readonly markdownService = inject(MarkdownService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly note = signal<ApiContent | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  /** Sanitized HTML — MarkdownService uses DOMPurify, safe for [innerHTML] */
  protected readonly parsedContent = computed(() => {
    const n = this.note();
    if (!n) {
      return '';
    }
    const body = n.body.replace(/^#\s+.+\n+/, '');
    return this.markdownService.parse(body);
  });

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;

  ngOnInit(): void {
    this.loadNote(this.slug());
  }

  private loadNote(slug: string): void {
    this.contentService.getBySlug(slug).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (note) => {
        this.note.set(note);
        this.isLoading.set(false);
        this.seoService.updateMeta({
          title: note.title,
          description: note.excerpt || note.body.slice(0, 160),
          ogUrl: `${environment.siteUrl}/notes/${note.slug}`,
          ogType: 'article',
        });
      },
      error: () => {
        this.error.set('Failed to load note');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }
}
