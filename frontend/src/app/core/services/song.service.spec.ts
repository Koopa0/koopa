import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import {
  SongService,
  todayISODate,
  type Song,
  type SongDetail,
  type SongReflection,
} from './song.service';

const BASE = '/api/admin/knowledge/songs';

function makeSong(overrides: Partial<Song> = {}): Song {
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
    ...overrides,
  };
}

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

describe('SongService', () => {
  let service: SongService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(SongService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should list songs when list is called', () => {
    let result: Song[] | undefined;
    service.list().subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'GET' && r.url.endsWith(BASE),
    );
    req.flush({ data: [makeSong(), makeSong({ id: 'sg-2' })] });

    expect(result?.length).toBe(2);
    expect(result?.[0].title_ja).toBe('春泥棒');
  });

  it('should fetch the song with its reflection thread when detail is called', () => {
    let result: SongDetail | undefined;
    service.detail('sg-1').subscribe((d) => (result = d));

    const req = httpMock.expectOne(
      (r) => r.method === 'GET' && r.url.endsWith(`${BASE}/sg-1`),
    );
    req.flush({ data: { ...makeSong(), reflections: [makeReflection()] } });

    expect(result?.title_ja).toBe('春泥棒');
    expect(result?.reflections.length).toBe(1);
    expect(result?.reflections[0].entry_date).toBe('2026-05-21');
  });

  it('should POST the create payload when create is called', () => {
    let result: Song | undefined;
    service
      .create({ title_ja: '夜行', album: '幻燈' })
      .subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(BASE),
    );
    expect(req.request.body).toEqual({ title_ja: '夜行', album: '幻燈' });
    req.flush({ data: makeSong({ id: 'sg-3', title_ja: '夜行', album: '幻燈' }) });

    expect(result?.title_ja).toBe('夜行');
  });

  it('should PUT the study-layer payload when update is called', () => {
    let result: Song | undefined;
    service
      .update('sg-1', { translation: 'Revised translation' })
      .subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(`${BASE}/sg-1`),
    );
    expect(req.request.body).toEqual({ translation: 'Revised translation' });
    req.flush({ data: makeSong({ translation: 'Revised translation' }) });

    expect(result?.translation).toBe('Revised translation');
  });

  it('should DELETE the song when remove is called', () => {
    let completed = false;
    service.remove('sg-1').subscribe(() => (completed = true));

    const req = httpMock.expectOne(
      (r) => r.method === 'DELETE' && r.url.endsWith(`${BASE}/sg-1`),
    );
    req.flush(null, { status: 204, statusText: 'No Content' });

    expect(completed).toBe(true);
  });

  it('should POST the entry to the song thread when addReflection is called', () => {
    let result: SongReflection | undefined;
    service
      .addReflection('sg-1', { body: 'A note.', entry_date: '2026-06-09' })
      .subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(`${BASE}/sg-1/reflections`),
    );
    expect(req.request.body).toEqual({ body: 'A note.', entry_date: '2026-06-09' });
    req.flush({ data: makeReflection({ body: 'A note.' }) });

    expect(result?.body).toBe('A note.');
  });

  it('should DELETE the entry when removeReflection is called', () => {
    let completed = false;
    service.removeReflection('sg-1', 'ref-1').subscribe(() => (completed = true));

    const req = httpMock.expectOne(
      (r) =>
        r.method === 'DELETE' &&
        r.url.endsWith(`${BASE}/sg-1/reflections/ref-1`),
    );
    req.flush(null, { status: 204, statusText: 'No Content' });

    expect(completed).toBe(true);
  });

  it('should format todayISODate as a local YYYY-MM-DD string', () => {
    expect(todayISODate()).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});
