import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import {
  ReadingService,
  todayISODate,
  type Reading,
  type ReadingDetail,
  type ReadingReflection,
} from './reading.service';

const BASE = '/api/admin/knowledge/readings';

function makeReading(overrides: Partial<Reading> = {}): Reading {
  return {
    id: 'rd-1',
    title: 'The Makioka Sisters',
    author: 'Junichiro Tanizaki',
    status: 'reading',
    started_on: '2026-05-20',
    finished_on: null,
    is_public: false,
    created_at: '2026-05-20T00:00:00Z',
    updated_at: '2026-06-01T00:00:00Z',
    ...overrides,
  };
}

function makeReflection(
  overrides: Partial<ReadingReflection> = {},
): ReadingReflection {
  return {
    id: 'ref-1',
    reading_id: 'rd-1',
    entry_date: '2026-05-21',
    body: 'The opening chapter lingers on the seasons.',
    created_at: '2026-05-21T00:00:00Z',
    updated_at: '2026-05-21T00:00:00Z',
    ...overrides,
  };
}

describe('ReadingService', () => {
  let service: ReadingService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(ReadingService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should list readings when list is called without a filter', () => {
    let result: Reading[] | undefined;
    service.list().subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'GET' && r.url.endsWith(BASE),
    );
    expect(req.request.params.has('status')).toBe(false);
    req.flush({ data: [makeReading(), makeReading({ id: 'rd-2' })] });

    expect(result?.length).toBe(2);
    expect(result?.[0].title).toBe('The Makioka Sisters');
  });

  it('should pass the status query param when list is called with a filter', () => {
    service.list('finished').subscribe();

    const req = httpMock.expectOne(
      (r) => r.method === 'GET' && r.url.endsWith(BASE),
    );
    expect(req.request.params.get('status')).toBe('finished');
    req.flush({ data: [] });
  });

  it('should fetch the reading with its reflection thread when detail is called', () => {
    let result: ReadingDetail | undefined;
    service.detail('rd-1').subscribe((d) => (result = d));

    const req = httpMock.expectOne(
      (r) => r.method === 'GET' && r.url.endsWith(`${BASE}/rd-1`),
    );
    req.flush({
      data: { ...makeReading(), reflections: [makeReflection()] },
    });

    expect(result?.title).toBe('The Makioka Sisters');
    expect(result?.reflections.length).toBe(1);
    expect(result?.reflections[0].entry_date).toBe('2026-05-21');
  });

  it('should POST the create payload when create is called', () => {
    let result: Reading | undefined;
    service
      .create({ title: 'Kokoro', author: 'Natsume Soseki' })
      .subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(BASE),
    );
    expect(req.request.body).toEqual({
      title: 'Kokoro',
      author: 'Natsume Soseki',
    });
    req.flush({
      data: makeReading({ id: 'rd-3', title: 'Kokoro', status: 'want_to_read' }),
    });

    expect(result?.status).toBe('want_to_read');
  });

  it('should PUT the partial payload when update is called', () => {
    let result: Reading | undefined;
    service.update('rd-1', { status: 'finished' }).subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(`${BASE}/rd-1`),
    );
    expect(req.request.body).toEqual({ status: 'finished' });
    req.flush({
      data: makeReading({ status: 'finished', finished_on: '2026-06-10' }),
    });

    expect(result?.finished_on).toBe('2026-06-10');
  });

  it('should DELETE the reading when remove is called', () => {
    let completed = false;
    service.remove('rd-1').subscribe(() => (completed = true));

    const req = httpMock.expectOne(
      (r) => r.method === 'DELETE' && r.url.endsWith(`${BASE}/rd-1`),
    );
    req.flush(null, { status: 204, statusText: 'No Content' });

    expect(completed).toBe(true);
  });

  it('should POST the entry to the reading thread when addReflection is called', () => {
    let result: ReadingReflection | undefined;
    service
      .addReflection('rd-1', { body: 'A note.', entry_date: '2026-06-09' })
      .subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(`${BASE}/rd-1/reflections`),
    );
    expect(req.request.body).toEqual({
      body: 'A note.',
      entry_date: '2026-06-09',
    });
    req.flush({ data: makeReflection({ body: 'A note.' }) });

    expect(result?.body).toBe('A note.');
  });

  it('should PUT the partial entry payload when updateReflection is called', () => {
    let result: ReadingReflection | undefined;
    service
      .updateReflection('rd-1', 'ref-1', { body: 'Revised.' })
      .subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) =>
        r.method === 'PUT' &&
        r.url.endsWith(`${BASE}/rd-1/reflections/ref-1`),
    );
    expect(req.request.body).toEqual({ body: 'Revised.' });
    req.flush({ data: makeReflection({ body: 'Revised.' }) });

    expect(result?.body).toBe('Revised.');
  });

  it('should DELETE the entry when removeReflection is called', () => {
    let completed = false;
    service.removeReflection('rd-1', 'ref-1').subscribe(() => (completed = true));

    const req = httpMock.expectOne(
      (r) =>
        r.method === 'DELETE' &&
        r.url.endsWith(`${BASE}/rd-1/reflections/ref-1`),
    );
    req.flush(null, { status: 204, statusText: 'No Content' });

    expect(completed).toBe(true);
  });

  it('should format todayISODate as a local YYYY-MM-DD string', () => {
    expect(todayISODate()).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});
