import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Calendar,
  StickyNote,
  Code,
  Settings,
  BookOpen,
  MoreHorizontal,
} from 'lucide-angular';
import { NoteService } from '../../core/services/note.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import type { NoteCategory } from '../../core/models/note.model';

interface CategoryTab {
  label: string;
  value: NoteCategory | 'all';
  icon: typeof Code;
}

@Component({
  selector: 'app-notes',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './notes.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class NotesComponent {
  private readonly noteService = inject(NoteService);
  private readonly seoService = inject(SeoService);

  protected readonly notes = this.noteService.publishedNotes;
  protected readonly selectedCategory = signal<NoteCategory | 'all'>('all');

  protected readonly filteredNotes = computed(() => {
    const cat = this.selectedCategory();
    if (cat === 'all') {
      return this.notes();
    }
    return this.noteService.getByCategory(cat);
  });

  protected readonly categories: CategoryTab[] = [
    { label: 'All', value: 'all', icon: StickyNote },
    { label: 'Snippet', value: 'snippet', icon: Code },
    { label: 'Config', value: 'config', icon: Settings },
    { label: 'Reading', value: 'reading', icon: BookOpen },
    { label: 'Other', value: 'other', icon: MoreHorizontal },
  ];

  protected readonly CalendarIcon = Calendar;
  protected readonly StickyNoteIcon = StickyNote;

  constructor() {
    this.seoService.updateMeta({
      title: 'Notes',
      description: '技術筆記 — 程式碼片段、設定檔備忘、閱讀筆記',
      ogUrl: 'https://koopa0.dev/notes',
    });
  }

  protected selectCategory(category: NoteCategory | 'all'): void {
    this.selectedCategory.set(category);
  }
}
