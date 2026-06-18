import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { SongShelfPageComponent } from './song-shelf.page';
import { type Song } from '../../../../core/services/song.service';

const SONGS_URL = '/api/admin/knowledge/songs';

function makeSong(overrides: Partial<Song> = {}): Song {
  return {
    id: 'sg-1',
    title_ja: '春泥棒',
    album: '創作',
    lyrics_ja: '',
    translation: '',
    vocabulary: '',
    is_public: false,
    created_at: '2026-05-20T00:00:00Z',
    updated_at: '2026-06-01T00:00:00Z',
    ...overrides,
  };
}

describe('SongShelfPageComponent', () => {
  let fixture: ComponentFixture<SongShelfPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SongShelfPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(SongShelfPageComponent);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushList(songs: Song[]): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(SONGS_URL))
      .flush({ data: songs });
  }

  it('should group songs by album in first-appearance order with no-album last', async () => {
    await settle();
    flushList([
      makeSong({ id: 'sg-1', title_ja: '春泥棒', album: '創作' }),
      makeSong({ id: 'sg-2', title_ja: '靴の花火', album: '夏草が邪魔をする' }),
      makeSong({ id: 'sg-3', title_ja: '雨とカプチーノ', album: '創作' }),
      makeSong({ id: 'sg-4', title_ja: 'ただ君に晴れ', album: '' }),
    ]);
    await settle();

    const groups = Array.from(
      el().querySelectorAll('[data-testid^="song-group-"]'),
    ).map((s) => s.getAttribute('data-testid'));
    expect(groups).toEqual([
      'song-group-創作',
      'song-group-夏草が邪魔をする',
      'song-group-none',
    ]);

    expect(el().textContent).toContain('No album');
    expect(el().textContent).toContain('春泥棒');
    expect(el().textContent).toContain('雨とカプチーノ');
    expect(
      el().querySelector('[data-testid="song-shelf-count"]')?.textContent,
    ).toContain('4 songs');
  });

  it('should mark a public song with the public tag', async () => {
    await settle();
    flushList([makeSong({ id: 'sg-1', is_public: true })]);
    await settle();

    expect(el().querySelector('[data-testid="song-row-public"]')).toBeTruthy();
  });

  it('should POST the new song and close the form when add song is submitted', async () => {
    await settle();
    flushList([]);
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-empty-add"]')
      ?.click();
    await settle();

    const title = el().querySelector<HTMLInputElement>(
      '[data-testid="song-add-title"]',
    );
    expect(title).toBeTruthy();
    title!.value = '夜行';
    title!.dispatchEvent(new Event('input'));
    const album = el().querySelector<HTMLInputElement>(
      '[data-testid="song-add-album"]',
    );
    album!.value = '幻燈';
    album!.dispatchEvent(new Event('input'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-add-submit"]')
      ?.click();
    await settle();

    const post = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(SONGS_URL),
    );
    expect(post.request.body).toEqual({ title_ja: '夜行', album: '幻燈' });
    post.flush({ data: makeSong({ id: 'sg-n', title_ja: '夜行', album: '幻燈' }) });
    await settle();

    flushList([makeSong({ id: 'sg-n', title_ja: '夜行', album: '幻燈' })]);
    await settle();

    expect(el().querySelector('[data-testid="song-add-form"]')).toBeNull();
    expect(el().textContent).toContain('夜行');
  });

  it('should show the teaching empty state when the shelf has no songs', async () => {
    await settle();
    flushList([]);
    await settle();

    const empty = el().querySelector('[data-testid="song-shelf-empty"]');
    expect(empty).toBeTruthy();
    expect(empty?.textContent).toContain('The shelf is empty.');
    expect(el().querySelector('[data-testid="song-empty-add"]')).toBeTruthy();
  });

  it('should show the error state and re-request on retry when the read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(SONGS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(el().querySelector('[data-testid="song-shelf-error"]')).toBeTruthy();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="song-shelf-retry"]')
      ?.click();
    await settle();

    flushList([makeSong()]);
    await settle();

    expect(el().querySelector('[data-testid="song-shelf-error"]')).toBeNull();
    expect(el().textContent).toContain('春泥棒');
  });
});
