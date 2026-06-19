import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router, type Routes } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';

import { NoteEditorPageComponent } from './note-editor.page';
import type { NoteDetail } from '../../../../core/services/note.service';

const NOTES_URL = '/api/admin/knowledge/notes';

const routes: Routes = [
  { path: 'admin/knowledge/notes/new', component: NoteEditorPageComponent },
  {
    path: 'admin/knowledge/notes/:id/edit',
    component: NoteEditorPageComponent,
  },
];

function notePayload(overrides: Partial<NoteDetail> = {}): NoteDetail {
  return {
    id: 'n-1',
    slug: 'binary-search-bounds',
    title: 'Binary search bounds',
    body: 'Lower bound vs upper bound.',
    kind: 'solve-note',
    maturity: 'seed',
    created_by: 'human',
    created_at: '2026-06-01T00:00:00Z',
    updated_at: '2026-06-02T00:00:00Z',
    ...overrides,
  };
}

describe('NoteEditorPageComponent', () => {
  let harness: RouterTestingHarness;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter(routes),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return harness.routeNativeElement as HTMLElement;
  }

  async function settle(): Promise<void> {
    harness.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    harness.detectChanges();
  }

  function setValue(selector: string, value: string): void {
    const input = el().querySelector<HTMLInputElement | HTMLTextAreaElement>(
      selector,
    );
    expect(input).toBeTruthy();
    input!.value = value;
    input!.dispatchEvent(new Event('input'));
  }

  describe('create mode', () => {
    beforeEach(async () => {
      harness = await RouterTestingHarness.create('/admin/knowledge/notes/new');
      await settle();
    });

    it('should render an empty form with slug input and no maturity ladder', () => {
      expect(el().querySelector('[data-testid="note-editor"]')).toBeTruthy();
      expect(el().querySelector('[data-testid="note-slug-input"]')).toBeTruthy();
      expect(
        el().querySelector('[data-testid="note-maturity-ladder"]'),
      ).toBeNull();
      expect(
        el().querySelector('[data-testid="note-create-hint"]')?.textContent,
      ).toContain('not created yet');
    });

    it('should offer all six kinds in the kind select', () => {
      const options = el().querySelectorAll<HTMLOptionElement>(
        '[data-testid="note-kind"] option',
      );
      expect(Array.from(options).map((o) => o.value)).toEqual([
        'solve-note',
        'concept-note',
        'debug-postmortem',
        'decision-log',
        'reading-note',
        'musing',
      ]);
    });

    it('should POST the new note and navigate to its edit route on submit', async () => {
      setValue('[data-testid="note-slug-input"]', 'my-new-note');
      setValue('[data-testid="note-title"]', 'My new note');
      setValue('[data-testid="note-body"]', 'Body text');
      await settle();

      el()
        .querySelector<HTMLFormElement>('[data-testid="note-editor"]')
        ?.dispatchEvent(new Event('submit'));
      await settle();

      const req = httpMock.expectOne(
        (r) => r.method === 'POST' && r.url.endsWith(NOTES_URL),
      );
      expect(req.request.body).toMatchObject({
        slug: 'my-new-note',
        title: 'My new note',
        body: 'Body text',
        kind: 'solve-note',
      });
      req.flush({
        data: notePayload({ id: 'created-7', slug: 'my-new-note' }),
      });
      await settle();

      expect(TestBed.inject(Router).url).toBe(
        '/admin/knowledge/notes/created-7/edit',
      );
      // The edit route instance loads the created note.
      httpMock
        .expectOne((r) => r.url.endsWith(`${NOTES_URL}/created-7`))
        .flush({ data: notePayload({ id: 'created-7' }) });
      await settle();
    });

    it('should not POST when required fields are missing', async () => {
      el()
        .querySelector<HTMLFormElement>('[data-testid="note-editor"]')
        ?.dispatchEvent(new Event('submit'));
      await settle();

      httpMock.expectNone(
        (r) => r.method === 'POST' && r.url.endsWith(NOTES_URL),
      );
    });
  });

  describe('edit mode', () => {
    beforeEach(async () => {
      harness = await RouterTestingHarness.create(
        '/admin/knowledge/notes/n-1/edit',
      );
      await settle();
      httpMock
        .expectOne((r) => r.url.endsWith(`${NOTES_URL}/n-1`))
        .flush({ data: notePayload() });
      await settle();
    });

    it('should render the maturity ladder with the current step marked', () => {
      expect(
        el().querySelector('[data-testid="note-maturity-ladder"]'),
      ).toBeTruthy();
      expect(el().querySelector('[data-testid="note-slug-input"]')).toBeNull();
      const current = el().querySelector<HTMLButtonElement>(
        '[data-testid="note-maturity-seed"]',
      );
      expect(current?.disabled).toBe(true);
      expect(current?.textContent).toContain('current');
    });

    it('should POST the maturity endpoint when a forward step is clicked', async () => {
      el()
        .querySelector<HTMLButtonElement>('[data-testid="note-maturity-stub"]')
        ?.click();
      await settle();

      const req = httpMock.expectOne(
        (r) =>
          r.method === 'POST' && r.url.endsWith(`${NOTES_URL}/n-1/maturity`),
      );
      expect(req.request.body).toEqual({ maturity: 'stub' });
      req.flush({ data: notePayload({ maturity: 'stub' }) });
      await settle();

      httpMock
        .expectOne((r) => r.url.endsWith(`${NOTES_URL}/n-1`))
        .flush({ data: notePayload({ maturity: 'stub' }) });
      await settle();

      expect(
        el().querySelector<HTMLButtonElement>(
          '[data-testid="note-maturity-stub"]',
        )?.disabled,
      ).toBe(true);
    });

    it('should PUT the note on submit and reload', async () => {
      setValue('[data-testid="note-title"]', 'Renamed note');
      await settle();

      el()
        .querySelector<HTMLFormElement>('[data-testid="note-editor"]')
        ?.dispatchEvent(new Event('submit'));
      await settle();

      const req = httpMock.expectOne(
        (r) => r.method === 'PUT' && r.url.endsWith(`${NOTES_URL}/n-1`),
      );
      expect(req.request.body).toMatchObject({ title: 'Renamed note' });
      req.flush({ data: notePayload({ title: 'Renamed note' }) });
      await settle();

      httpMock
        .expectOne(
          (r) => r.method === 'GET' && r.url.endsWith(`${NOTES_URL}/n-1`),
        )
        .flush({ data: notePayload({ title: 'Renamed note' }) });
      await settle();
    });
  });
});
