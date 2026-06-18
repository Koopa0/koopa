import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router, type Routes } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';

import { SongDetailPageComponent } from './song-detail.page';
import {
  todayISODate,
  type SongDetail,
  type SongReflection,
} from '../../../../core/services/song.service';

const DETAIL_URL = '/api/admin/knowledge/songs/sg-1';

/** Navigation target for the post-delete redirect. */
@Component({ selector: 'app-shelf-stub', template: '' })
class ShelfStubComponent {}

const routes: Routes = [
  { path: 'admin/knowledge/song', component: ShelfStubComponent },
  { path: 'admin/knowledge/song/:id', component: SongDetailPageComponent },
];

function makeReflection(
  overrides: Partial<SongReflection> = {},
): SongReflection {
  return {
    id: 'ref-1',
    song_id: 'sg-1',
    entry_date: '2026-05-21',
    body: 'The bridge metaphor finally clicked.',
    created_at: '2026-05-21T00:00:00Z',
    updated_at: '2026-05-21T00:00:00Z',
    ...overrides,
  };
}

function detailPayload(overrides: Partial<SongDetail> = {}): SongDetail {
  return {
    id: 'sg-1',
    title_ja: '春泥棒',
    album: '創作',
    lyrics_ja: '高架橋を抜けたら',
    translation: 'Once past the overpass',
    vocabulary: '高架橋 — elevated bridge',
    is_public: false,
    created_at: '2026-05-20T00:00:00Z',
    updated_at: '2026-06-01T00:00:00Z',
    reflections: [
      makeReflection(),
      makeReflection({
        id: 'ref-2',
        entry_date: '2026-05-28',
        body: 'Listened on the train.\nThe seasons line lands differently now.',
      }),
    ],
    ...overrides,
  };
}

describe('SongDetailPageComponent', () => {
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
    vi.restoreAllMocks();
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

  function flushDetail(payload: SongDetail): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(DETAIL_URL))
      .flush({ data: payload });
  }

  async function open(payload: SongDetail = detailPayload()): Promise<void> {
    harness = await RouterTestingHarness.create('/admin/knowledge/song/sg-1');
    await settle();
    flushDetail(payload);
    await settle();
  }

  it('should render the header, the seeded study layer, and the diary thread', async () => {
    await open();

    expect(
      el().querySelector('[data-testid="song-detail-title"]')?.textContent,
    ).toContain('春泥棒');
    expect(
      el().querySelector('[data-testid="song-detail-album"]')?.textContent,
    ).toContain('創作');
    expect(
      el().querySelector<HTMLInputElement>('[data-testid="song-study-title"]')
        ?.value,
    ).toBe('春泥棒');
    expect(
      el().querySelector<HTMLTextAreaElement>(
        '[data-testid="song-study-translation"]',
      )?.value,
    ).toBe('Once past the overpass');

    const entries = el().querySelectorAll('[data-testid^="song-entry-row-"]');
    expect(entries.length).toBe(2);
    expect(entries[0].textContent).toContain('2026-05-21');
    expect(el().querySelector('[data-testid="song-composer"]')).toBeTruthy();
  });

  it('should PUT the whole study layer when save study fields is clicked after an edit', async () => {
    await open();

    // Not dirty on load — the save button is disabled.
    expect(
      el().querySelector<HTMLButtonElement>('[data-testid="song-study-save"]')
        ?.disabled,
    ).toBe(true);

    const translation = el().querySelector<HTMLTextAreaElement>(
      '[data-testid="song-study-translation"]',
    );
    translation!.value = 'A new translation';
    translation!.dispatchEvent(new Event('input'));
    await settle();

    expect(el().querySelector('[data-testid="song-study-dirty"]')).toBeTruthy();
    expect(
      el().querySelector<HTMLButtonElement>('[data-testid="song-study-save"]')
        ?.disabled,
    ).toBe(false);

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-study-save"]')
      ?.click();
    await settle();

    const put = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(DETAIL_URL),
    );
    expect(put.request.body).toEqual({
      title_ja: '春泥棒',
      album: '創作',
      lyrics_ja: '高架橋を抜けたら',
      translation: 'A new translation',
      vocabulary: '高架橋 — elevated bridge',
    });
    put.flush({ data: detailPayload({ translation: 'A new translation' }) });
    await settle();

    flushDetail(detailPayload({ translation: 'A new translation' }));
    await settle();

    // After reload the linkedSignal re-syncs — no unsaved-changes left.
    expect(el().querySelector('[data-testid="song-study-dirty"]')).toBeNull();
  });

  it('should disable the study save when the title is blanked', async () => {
    await open();

    const title = el().querySelector<HTMLInputElement>(
      '[data-testid="song-study-title"]',
    );
    title!.value = '   ';
    title!.dispatchEvent(new Event('input'));
    await settle();

    expect(
      el().querySelector<HTMLButtonElement>('[data-testid="song-study-save"]')
        ?.disabled,
    ).toBe(true);
  });

  it('should POST the entry with the chosen date when the composer is submitted', async () => {
    await open();

    const body = el().querySelector<HTMLTextAreaElement>(
      '[data-testid="song-composer-body"]',
    );
    body!.value = 'A quiet listen.';
    body!.dispatchEvent(new Event('input'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-composer-submit"]')
      ?.click();
    await settle();

    const post = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(`${DETAIL_URL}/reflections`),
    );
    expect(post.request.body).toEqual({
      body: 'A quiet listen.',
      entry_date: todayISODate(),
    });
    post.flush({ data: makeReflection({ id: 'ref-3', body: 'A quiet listen.' }) });
    await settle();

    flushDetail(
      detailPayload({
        reflections: [
          makeReflection(),
          makeReflection({ id: 'ref-3', body: 'A quiet listen.' }),
        ],
      }),
    );
    await settle();

    expect(
      el().querySelector<HTMLTextAreaElement>(
        '[data-testid="song-composer-body"]',
      )?.value,
    ).toBe('');
    expect(el().textContent).toContain('A quiet listen.');
  });

  it('should DELETE the entry after confirmation when delete is clicked', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await open();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-entry-delete-0"]')
      ?.click();
    await settle();

    httpMock
      .expectOne(
        (r) =>
          r.method === 'DELETE' &&
          r.url.endsWith(`${DETAIL_URL}/reflections/ref-1`),
      )
      .flush(null, { status: 204, statusText: 'No Content' });
    await settle();

    flushDetail(
      detailPayload({
        reflections: [makeReflection({ id: 'ref-2', entry_date: '2026-05-28' })],
      }),
    );
    await settle();

    expect(
      el().querySelectorAll('[data-testid^="song-entry-row-"]').length,
    ).toBe(1);
  });

  it('should DELETE the song and return to the shelf when delete is confirmed', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await open();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-menu-toggle"]')
      ?.click();
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-menu-delete"]')
      ?.click();
    await settle();

    expect(confirmSpy).toHaveBeenCalledWith(
      'Delete "春泥棒"? Its 2 diary entries go with it.',
    );

    httpMock
      .expectOne((r) => r.method === 'DELETE' && r.url.endsWith(DETAIL_URL))
      .flush(null, { status: 204, statusText: 'No Content' });
    await settle();

    expect(TestBed.inject(Router).url).toBe('/admin/knowledge/song');
  });

  it('should show the inviting empty-thread copy when the diary has no entries', async () => {
    await open(detailPayload({ reflections: [] }));

    const empty = el().querySelector('[data-testid="song-thread-empty"]');
    expect(empty).toBeTruthy();
    expect(el().querySelector('[data-testid="song-composer"]')).toBeTruthy();
  });

  it('should show the error state and re-request on retry when the read fails', async () => {
    harness = await RouterTestingHarness.create('/admin/knowledge/song/sg-1');
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(DETAIL_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(el().querySelector('[data-testid="song-detail-error"]')).toBeTruthy();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-detail-retry"]')
      ?.click();
    await settle();

    flushDetail(detailPayload());
    await settle();

    expect(el().querySelector('[data-testid="song-detail-error"]')).toBeNull();
    expect(
      el().querySelector('[data-testid="song-detail-title"]')?.textContent,
    ).toContain('春泥棒');
  });
});
