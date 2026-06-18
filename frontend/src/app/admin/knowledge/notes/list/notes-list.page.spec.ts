import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { NotesListPageComponent } from './notes-list.page';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { NoteRow } from '../../../../core/services/note.service';

// Mocks only the real HTTP boundary (GET /api/admin/knowledge/notes). The
// guarded loadedRows() reads hasValue() ? value() : [] — a failed read must
// fall back to [] and surface the error banner rather than throw a
// ResourceValueError. A plain 500 (not 404/405/501) drives the generic
// `notes-list-error` banner, not the endpoints-pending placeholder.
const LIST_URL = '/api/admin/knowledge/notes';

function note(overrides: Partial<NoteRow> = {}): NoteRow {
  return {
    id: 'n0000000-0000-0000-0000-000000000001',
    slug: 'pgvector-indexing',
    title: 'pgvector indexing notes',
    kind: 'concept-note',
    maturity: 'seed',
    created_by: 'human',
    concepts: [],
    targets: [],
    created_at: '2026-06-01T10:00:00Z',
    updated_at: '2026-06-10T10:00:00Z',
    ...overrides,
  };
}

describe('NotesListPageComponent', () => {
  let fixture: ComponentFixture<NotesListPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NotesListPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  async function settle(): Promise<void> {
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
  }

  it('should render a row per note from the bare data array', async () => {
    fixture = TestBed.createComponent(NotesListPageComponent);
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(LIST_URL))
      .flush({ data: [note({ title: 'pgvector indexing notes' })] });
    await settle();

    expect(testid('notes-list-row-0')?.textContent).toContain(
      'pgvector indexing notes',
    );
    expect(testid('notes-count')?.textContent).toContain('1');
  });

  it('should surface the error banner without throwing when the list read fails', async () => {
    fixture = TestBed.createComponent(NotesListPageComponent);
    fixture.detectChanges();
    // Fail the read with a 500. loadedRows() must fall back to [] via the
    // hasValue() guard rather than throw a ResourceValueError, and the generic
    // error banner must render.
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(LIST_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await settle();

    expect(testid('notes-list-error')).not.toBeNull();
    expect(testid('notes-endpoints-pending')).toBeNull();
    expect(testid('notes-list-row-0')).toBeNull();
  });
});
