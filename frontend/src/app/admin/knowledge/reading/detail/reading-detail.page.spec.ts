import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router, type Routes } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';

import { ReadingDetailPageComponent } from './reading-detail.page';
import {
  todayISODate,
  type ReadingDetail,
  type ReadingReflection,
} from '../../../../core/services/reading.service';

const DETAIL_URL = '/api/admin/knowledge/readings/rd-1';

/** Navigation target for the post-delete redirect. */
@Component({ selector: 'app-shelf-stub', template: '' })
class ShelfStubComponent {}

const routes: Routes = [
  { path: 'admin/knowledge/reading', component: ShelfStubComponent },
  { path: 'admin/knowledge/reading/:id', component: ReadingDetailPageComponent },
];

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

function detailPayload(overrides: Partial<ReadingDetail> = {}): ReadingDetail {
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
    reflections: [
      makeReflection(),
      makeReflection({
        id: 'ref-2',
        entry_date: '2026-05-28',
        body: 'Yukiko refuses again.\nThe family pretends not to mind.',
      }),
    ],
    ...overrides,
  };
}

describe('ReadingDetailPageComponent', () => {
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

  function flushDetail(payload: ReadingDetail): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(DETAIL_URL))
      .flush({ data: payload });
  }

  async function open(payload: ReadingDetail = detailPayload()): Promise<void> {
    harness = await RouterTestingHarness.create('/admin/knowledge/reading/rd-1');
    await settle();
    flushDetail(payload);
    await settle();
  }

  it('should render the book header and the diary thread in entry order', async () => {
    await open();

    expect(
      el().querySelector('[data-testid="reading-detail-title"]')?.textContent,
    ).toContain('The Makioka Sisters');
    expect(
      el().querySelector('[data-testid="reading-detail-author"]')?.textContent,
    ).toContain('Junichiro Tanizaki');
    expect(
      el().querySelector<HTMLSelectElement>(
        '[data-testid="reading-status-select"]',
      )?.value,
    ).toBe('reading');
    expect(
      el().querySelector<HTMLInputElement>(
        '[data-testid="reading-started-input"]',
      )?.value,
    ).toBe('2026-05-20');

    const entries = el().querySelectorAll('[data-testid^="reading-entry-row-"]');
    expect(entries.length).toBe(2);
    expect(entries[0].textContent).toContain('2026-05-21');
    expect(entries[1].textContent).toContain('Yukiko refuses again.');
    expect(el().querySelector('[data-testid="reading-composer"]')).toBeTruthy();
  });

  it('should POST the entry with the chosen date when the composer is submitted', async () => {
    await open();

    const body = el().querySelector<HTMLTextAreaElement>(
      '[data-testid="reading-composer-body"]',
    );
    body!.value = 'A quiet chapter.';
    body!.dispatchEvent(new Event('input'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="reading-composer-submit"]',
      )
      ?.click();
    await settle();

    const post = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(`${DETAIL_URL}/reflections`),
    );
    expect(post.request.body).toEqual({
      body: 'A quiet chapter.',
      entry_date: todayISODate(),
    });
    post.flush({ data: makeReflection({ id: 'ref-3', body: 'A quiet chapter.' }) });
    await settle();

    flushDetail(
      detailPayload({
        reflections: [
          makeReflection(),
          makeReflection({ id: 'ref-3', body: 'A quiet chapter.' }),
        ],
      }),
    );
    await settle();

    expect(
      el().querySelector<HTMLTextAreaElement>(
        '[data-testid="reading-composer-body"]',
      )?.value,
    ).toBe('');
    expect(el().textContent).toContain('A quiet chapter.');
  });

  it('should PUT the status without a date when the status control changes to finished', async () => {
    await open();

    const select = el().querySelector<HTMLSelectElement>(
      '[data-testid="reading-status-select"]',
    );
    select!.value = 'finished';
    select!.dispatchEvent(new Event('change'));
    await settle();

    const put = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(DETAIL_URL),
    );
    expect(put.request.body).toEqual({ status: 'finished' });
    put.flush({
      data: { ...detailPayload(), status: 'finished', finished_on: todayISODate() },
    });
    await settle();

    flushDetail(
      detailPayload({ status: 'finished', finished_on: todayISODate() }),
    );
    await settle();

    expect(
      el().querySelector<HTMLInputElement>(
        '[data-testid="reading-finished-input"]',
      )?.value,
    ).toBe(todayISODate());
  });

  it('should PUT the revised body and date when an entry edit is saved', async () => {
    await open();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-entry-edit-0"]')
      ?.click();
    await settle();

    const body = el().querySelector<HTMLTextAreaElement>(
      '[data-testid="reading-entry-edit-body"]',
    );
    expect(body?.value).toContain('The opening chapter');
    body!.value = 'Revised impression.';
    body!.dispatchEvent(new Event('input'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-entry-save"]')
      ?.click();
    await settle();

    const put = httpMock.expectOne(
      (r) =>
        r.method === 'PUT' && r.url.endsWith(`${DETAIL_URL}/reflections/ref-1`),
    );
    expect(put.request.body).toEqual({
      body: 'Revised impression.',
      entry_date: '2026-05-21',
    });
    put.flush({ data: makeReflection({ body: 'Revised impression.' }) });
    await settle();

    flushDetail(
      detailPayload({
        reflections: [makeReflection({ body: 'Revised impression.' })],
      }),
    );
    await settle();

    expect(el().textContent).toContain('Revised impression.');
  });

  it('should DELETE the entry after confirmation when delete is clicked', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await open();

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="reading-entry-delete-0"]',
      )
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
      el().querySelectorAll('[data-testid^="reading-entry-row-"]').length,
    ).toBe(1);
  });

  it('should not call the API when the entry delete confirmation is dismissed', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    await open();

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="reading-entry-delete-0"]',
      )
      ?.click();
    await settle();
    // afterEach httpMock.verify() asserts no DELETE went out.
  });

  it('should DELETE the book and return to the shelf when delete is confirmed from the overflow menu', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await open();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-menu-toggle"]')
      ?.click();
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-menu-delete"]')
      ?.click();
    await settle();

    expect(confirmSpy).toHaveBeenCalledWith(
      'Delete "The Makioka Sisters"? Its 2 diary entries go with it.',
    );

    httpMock
      .expectOne((r) => r.method === 'DELETE' && r.url.endsWith(DETAIL_URL))
      .flush(null, { status: 204, statusText: 'No Content' });
    await settle();

    expect(TestBed.inject(Router).url).toBe('/admin/knowledge/reading');
  });

  it('should show the inviting empty-thread copy when the diary has no entries', async () => {
    await open(detailPayload({ reflections: [] }));

    const empty = el().querySelector('[data-testid="reading-thread-empty"]');
    expect(empty).toBeTruthy();
    expect(empty?.textContent).toContain('a single sentence');
    expect(el().querySelector('[data-testid="reading-composer"]')).toBeTruthy();
  });

  it('should show the error state and re-request on retry when the read fails', async () => {
    harness = await RouterTestingHarness.create('/admin/knowledge/reading/rd-1');
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(DETAIL_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(
      el().querySelector('[data-testid="reading-detail-error"]'),
    ).toBeTruthy();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="reading-detail-retry"]')
      ?.click();
    await settle();

    flushDetail(detailPayload());
    await settle();

    expect(el().querySelector('[data-testid="reading-detail-error"]')).toBeNull();
    expect(
      el().querySelector('[data-testid="reading-detail-title"]')?.textContent,
    ).toContain('The Makioka Sisters');
  });
});
