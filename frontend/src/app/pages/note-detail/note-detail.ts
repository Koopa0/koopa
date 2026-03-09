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
} from 'lucide-angular';
import { NoteService } from '../../core/services/note.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { Note } from '../../core/models';

@Component({
  selector: 'app-note-detail',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './note-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class NoteDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly location = inject(Location);
  private readonly noteService = inject(NoteService);
  private readonly markdownService = inject(MarkdownService);
  private readonly sanitizer = inject(DomSanitizer);
  private readonly seoService = inject(SeoService);

  protected readonly note = signal<Note | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  // SECURITY_REVIEW: 內容由 MarkdownService 產生，非使用者可注入
  protected readonly parsedContent = computed<SafeHtml>(() => {
    const n = this.note();
    if (!n) {
      return '';
    }
    const html = this.markdownService.parse(n.content);
    return this.sanitizer.bypassSecurityTrustHtml(html);
  });

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CalendarIcon = Calendar;

  ngOnInit(): void {
    const slug = this.route.snapshot.paramMap.get('slug');
    if (slug) {
      this.loadNote(slug);
    } else {
      this.error.set('筆記不存在');
      this.isLoading.set(false);
    }
  }

  private loadNote(slug: string): void {
    this.noteService.getBySlug(slug).subscribe({
      next: (note) => {
        this.note.set(note);
        this.isLoading.set(false);
        this.seoService.updateMeta({
          title: note.title,
          description: note.content.slice(0, 160),
          ogUrl: `https://koopa0.dev/notes/${note.slug}`,
          ogType: 'article',
        });
      },
      error: () => {
        this.error.set('載入筆記失敗');
        this.isLoading.set(false);
      },
    });
  }

  protected goBack(): void {
    this.location.back();
  }
}
