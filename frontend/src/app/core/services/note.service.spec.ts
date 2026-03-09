import { TestBed } from '@angular/core/testing';
import { NoteService } from './note.service';

describe('NoteService', () => {
  let service: NoteService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(NoteService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should return published notes sorted by date desc', () => {
    const notes = service.publishedNotes();
    expect(notes.length).toBeGreaterThan(0);
    for (let i = 1; i < notes.length; i++) {
      expect(notes[i - 1].publishedAt.getTime()).toBeGreaterThanOrEqual(
        notes[i].publishedAt.getTime(),
      );
    }
  });

  it('should find note by slug', (done) => {
    service.getBySlug('go-dockerfile-multistage').subscribe({
      next: (note) => {
        expect(note.title).toContain('Dockerfile');
        done();
      },
    });
  });

  it('should filter by category', () => {
    const snippets = service.getByCategory('snippet');
    expect(snippets.length).toBeGreaterThan(0);
    expect(snippets.every((n) => n.category === 'snippet')).toBeTrue();
  });

  it('should filter by tag', () => {
    const goNotes = service.getByTag('Golang');
    expect(goNotes.length).toBeGreaterThan(0);
    expect(goNotes.every((n) => n.tags.includes('Golang'))).toBeTrue();
  });
});
