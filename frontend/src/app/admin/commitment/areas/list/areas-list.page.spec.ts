import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { AreasListPageComponent } from './areas-list.page';
import type { Area } from '../../../../core/services/plan.service';

const AREAS_URL = '/api/admin/commitment/areas';

const ROWS: Area[] = [
  { id: 'area-1', slug: 'career', name: 'Career', sort_order: 1 },
  { id: 'area-2', slug: 'health', name: 'Health', sort_order: 2 },
];

describe('AreasListPageComponent', () => {
  let fixture: ComponentFixture<AreasListPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AreasListPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
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

  /** Flush the single list GET; rxResource resolves on a macrotask. */
  async function render(body: Area[]): Promise<void> {
    fixture = TestBed.createComponent(AreasListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock.expectOne((r) => r.url.endsWith(AREAS_URL)).flush({ data: body });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should request the areas endpoint exactly once', async () => {
    fixture = TestBed.createComponent(AreasListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.endsWith(AREAS_URL));
    expect(req.request.method).toBe('GET');
    req.flush({ data: ROWS });
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('should render name, slug and sort_order from the areas read', async () => {
    await render(ROWS);

    expect(testid('areas-count')?.textContent).toContain('2 areas');
    const firstRow = testid('areas-list-row-0');
    expect(firstRow?.textContent).toContain('Career');
    expect(firstRow?.textContent).toContain('career');
    expect(firstRow?.textContent).toContain('1');
  });

  it('should render the empty state when there are no areas', async () => {
    await render([]);

    expect(testid('areas-count')?.textContent).toContain('0 areas');
    expect(el().textContent).toContain('No areas yet');
  });

  // flush-500: a failed load must NOT throw (hasValue() guard) and must
  // render the error banner. Without the guard, value() throws while the
  // resource is in error state and takes the page down.
  it('should surface the error banner when the list read fails (no throw)', async () => {
    fixture = TestBed.createComponent(AreasListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(AREAS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    expect(testid('areas-list-error')).not.toBeNull();
  });
});
