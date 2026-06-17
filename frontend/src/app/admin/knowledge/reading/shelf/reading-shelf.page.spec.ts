import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { ReadingShelfPageComponent } from './reading-shelf.page';
import {
  todayISODate,
  type Reading,
} from '../../../../core/services/reading.service';

const READINGS_URL = '/api/admin/knowledge/readings';

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

describe('ReadingShelfPageComponent', () => {
  let fixture: ComponentFixture<ReadingShelfPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ReadingShelfPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ReadingShelfPageComponent);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  /** Renders and lets the resource loader issue its HTTP request. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushList(readings: Reading[]): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(READINGS_URL))
      .flush({ data: readings });
  }

  it('should group books by status in shelf order when the list loads', async () => {
    await settle();
    flushList([
      makeReading({ id: 'rd-f', title: 'Kokoro', status: 'finished', finished_on: '2026-04-01' }),
      makeReading({ id: 'rd-w', title: 'Snow Country', author: 'Yasunari Kawabata', status: 'want_to_read', started_on: null }),
      makeReading({ id: 'rd-r', title: 'The Makioka Sisters', status: 'reading' }),
      makeReading({ id: 'rd-a', title: 'Ulysses', author: '', status: 'abandoned' }),
    ]);
    await settle();

    const groups = Array.from(
      el().querySelectorAll('[data-testid^="reading-group-"]'),
    ).map((s) => s.getAttribute('data-testid'));
    expect(groups).toEqual([
      'reading-group-reading',
      'reading-group-want_to_read',
      'reading-group-finished',
      'reading-group-abandoned',
    ]);

    expect(el().textContent).toContain('The Makioka Sisters');
    expect(el().textContent).toContain('Junichiro Tanizaki');
    expect(el().textContent).toContain('since 2026-05-20');
    expect(el().textContent).toContain('finished 2026-04-01');
    expect(
      el().querySelector('[data-testid="reading-shelf-count"]')?.textContent,
    ).toContain('4 books');
  });

  it('should PUT a reading transition with a start stamp when start reading is clicked', async () => {
    await settle();
    flushList([
      makeReading({ id: 'rd-w', status: 'want_to_read', started_on: null }),
    ]);
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-start-rd-w"]')
      ?.click();
    await settle();

    const put = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(`${READINGS_URL}/rd-w`),
    );
    expect(put.request.body).toEqual({
      status: 'reading',
      started_on: todayISODate(),
    });
    put.flush({ data: makeReading({ id: 'rd-w', status: 'reading' }) });
    await settle();

    flushList([makeReading({ id: 'rd-w', status: 'reading' })]);
    await settle();
    expect(
      el().querySelector('[data-testid="reading-group-reading"]'),
    ).toBeTruthy();
  });

  it('should PUT only the status and let the server stamp the date when finish is clicked', async () => {
    await settle();
    flushList([makeReading({ id: 'rd-r', status: 'reading' })]);
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-finish-rd-r"]')
      ?.click();
    await settle();

    const put = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(`${READINGS_URL}/rd-r`),
    );
    expect(put.request.body).toEqual({ status: 'finished' });
    put.flush({
      data: makeReading({ id: 'rd-r', status: 'finished', finished_on: todayISODate() }),
    });
    await settle();

    flushList([
      makeReading({ id: 'rd-r', status: 'finished', finished_on: todayISODate() }),
    ]);
    await settle();
  });

  it('should POST the new book and close the form when add book is submitted', async () => {
    await settle();
    flushList([]);
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-empty-add"]')
      ?.click();
    await settle();

    const title = el().querySelector<HTMLInputElement>(
      '[data-testid="reading-add-title"]',
    );
    expect(title).toBeTruthy();
    title!.value = 'Snow Country';
    title!.dispatchEvent(new Event('input'));
    const author = el().querySelector<HTMLInputElement>(
      '[data-testid="reading-add-author"]',
    );
    author!.value = 'Yasunari Kawabata';
    author!.dispatchEvent(new Event('input'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-add-submit"]')
      ?.click();
    await settle();

    const post = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(READINGS_URL),
    );
    expect(post.request.body).toEqual({
      title: 'Snow Country',
      author: 'Yasunari Kawabata',
      status: 'want_to_read',
    });
    post.flush({
      data: makeReading({
        id: 'rd-n',
        title: 'Snow Country',
        status: 'want_to_read',
      }),
    });
    await settle();

    flushList([
      makeReading({ id: 'rd-n', title: 'Snow Country', status: 'want_to_read' }),
    ]);
    await settle();

    expect(el().querySelector('[data-testid="reading-add-form"]')).toBeNull();
    expect(el().textContent).toContain('Snow Country');
  });

  it('should show the teaching empty state when the shelf has no books', async () => {
    await settle();
    flushList([]);
    await settle();

    const empty = el().querySelector('[data-testid="reading-shelf-empty"]');
    expect(empty).toBeTruthy();
    expect(empty?.textContent).toContain('The shelf is empty.');
    expect(
      el().querySelector('[data-testid="reading-empty-add"]'),
    ).toBeTruthy();
  });

  it('should show the error state and re-request on retry when the read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(READINGS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(
      el().querySelector('[data-testid="reading-shelf-error"]'),
    ).toBeTruthy();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-shelf-retry"]')
      ?.click();
    await settle();

    flushList([makeReading()]);
    await settle();

    expect(el().querySelector('[data-testid="reading-shelf-error"]')).toBeNull();
    expect(el().textContent).toContain('The Makioka Sisters');
  });
});
