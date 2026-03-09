import { Injectable, signal, computed } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';
import { Note, NoteCategory } from '../models/note.model';
import { MOCK_NOTES } from './mock-notes';

@Injectable({
  providedIn: 'root',
})
export class NoteService {
  private readonly notes = signal<Note[]>(MOCK_NOTES);

  readonly allNotes = this.notes.asReadonly();

  readonly publishedNotes = computed(() =>
    this.notes()
      .filter((n) => n.status === 'published')
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime()),
  );

  readonly latestNotes = computed(() => this.publishedNotes().slice(0, 5));

  getBySlug(slug: string): Observable<Note> {
    const note = this.notes().find(
      (n) => n.slug === slug && n.status === 'published',
    );
    if (!note) {
      return throwError(() => new Error('Note not found'));
    }
    return of(note);
  }

  getByCategory(category: NoteCategory): Note[] {
    return this.publishedNotes().filter((n) => n.category === category);
  }

  getByTag(tag: string): Note[] {
    return this.publishedNotes().filter((n) => n.tags.includes(tag));
  }
}
