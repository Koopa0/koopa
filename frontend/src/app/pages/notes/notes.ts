import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Calendar,
  StickyNote,
} from 'lucide-angular';
import { NoteService } from '../../core/services/note.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-notes',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './notes.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class NotesComponent implements OnInit {
  private readonly noteService = inject(NoteService);
  private readonly seoService = inject(SeoService);

  protected readonly notes = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly CalendarIcon = Calendar;
  protected readonly StickyNoteIcon = StickyNote;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Notes',
      description: '技術筆記 — 程式碼片段、設定檔備忘、閱讀筆記',
      ogUrl: 'https://koopa0.dev/notes',
    });
    this.loadNotes();
  }

  private loadNotes(): void {
    this.noteService.getNotes(1, 100).subscribe({
      next: (response) => {
        this.notes.set(response.notes);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('載入筆記失敗');
        this.isLoading.set(false);
      },
    });
  }
}
