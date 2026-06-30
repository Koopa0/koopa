import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { RoutinesPageComponent } from './routines.page';

const RECURRING_URL = '/api/admin/commitment/todos/recurring';

const recurringFixture = {
  due_today: [
    {
      id: 'r1',
      title: 'Morning Japanese',
      state: 'todo',
      recur_weekdays: 127,
      created_by: 'human',
      created_at: '2026-06-01T07:00:00Z',
      updated_at: '2026-06-01T07:00:00Z',
    },
  ],
  all: [
    {
      id: 'r1',
      title: 'Morning Japanese',
      state: 'todo',
      recur_weekdays: 127,
      last_completed_on: null,
      created_by: 'human',
      created_at: '2026-06-01T07:00:00Z',
      updated_at: '2026-06-01T07:00:00Z',
    },
    {
      id: 'r2',
      title: 'Weekly review',
      state: 'todo',
      recur_interval: 1,
      recur_unit: 'weeks',
      last_completed_on: '2026-06-28',
      created_by: 'human',
      created_at: '2026-06-01T07:00:00Z',
      updated_at: '2026-06-01T07:00:00Z',
    },
  ],
};

describe('RoutinesPageComponent', () => {
  let fixture: ComponentFixture<RoutinesPageComponent>;
  let httpMock: HttpTestingController;

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
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  async function render(): Promise<void> {
    TestBed.configureTestingModule({
      imports: [RoutinesPageComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(RoutinesPageComponent);
    fixture.detectChanges();
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(RECURRING_URL))
      .flush({ data: recurringFixture });
    await settle();
  }

  it('should list every active routine from the all bucket with its schedule', async () => {
    await render();

    const rows = el().querySelectorAll('[data-testid="routines-row"]');
    expect(rows.length).toBe(2);
    expect(rows[0]?.textContent).toContain('Morning Japanese');
    expect(rows[0]?.textContent).toContain('daily');
    expect(rows[1]?.textContent).toContain('Weekly review');
    expect(rows[1]?.textContent).toContain('every 1w');
  });

  it('should mark a routine due today and show last-completed for the others', async () => {
    await render();

    // r1 is in due_today → marked; never run.
    expect(testid('routines-due-today')).toBeTruthy();
    const rows = el().querySelectorAll('[data-testid="routines-row"]');
    expect(rows[0]?.textContent).toContain('never run');
    // r2 is not due today and ran on Jun 28.
    expect(rows[1]?.textContent).toContain('Jun 28');
  });

  it('should show the empty state when there are no routines', async () => {
    TestBed.configureTestingModule({
      imports: [RoutinesPageComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(RoutinesPageComponent);
    fixture.detectChanges();
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(RECURRING_URL))
      .flush({ data: { due_today: [], all: [] } });
    await settle();

    expect(el().textContent).toContain('No routines yet');
  });
});
