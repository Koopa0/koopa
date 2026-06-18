import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ClarifyModalComponent } from './clarify-modal.component';
import type { TodoRow } from '../../../core/services/todo.service';
import type { ClarifyResult } from './gtd-view';

const PROJECTS_URL = '/api/admin/commitment/projects';

const capture: TodoRow = {
  id: 'todo-1',
  title: 'Research pgvector indexing',
  state: 'inbox',
  created_at: '2026-06-10T08:00:00Z',
  updated_at: '2026-06-10T08:00:00Z',
};

describe('ClarifyModalComponent', () => {
  let fixture: ComponentFixture<ClarifyModalComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  async function render(): Promise<void> {
    fixture = TestBed.createComponent(ClarifyModalComponent);
    fixture.componentRef.setInput('item', capture);
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.includes(PROJECTS_URL))
      .flush({
        data: {
          projects: [
            {
              id: 'proj-1',
              title: 'koopa-core',
              slug: 'koopa-core',
              status: 'active',
              area: 'work',
              goal_breadcrumb: null,
              task_progress: { done: 0, total: 0 },
              staleness_days: 0,
              last_activity_at: null,
            },
          ],
        },
      });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  function testid(id: string): HTMLElement | null {
    return (fixture.nativeElement as HTMLElement).querySelector(
      `[data-testid="${id}"]`,
    );
  }

  it('should render the capture title and load project options', async () => {
    await render();
    const host = fixture.nativeElement as HTMLElement;
    expect(host.textContent).toContain('Research pgvector indexing');
    const select = testid('clarify-project') as HTMLSelectElement;
    expect(select.options).toHaveLength(2);
    expect(select.options[1].textContent).toContain('koopa-core');
  });

  it('should emit the clarify result with selected fields on submit', async () => {
    await render();
    const results: ClarifyResult[] = [];
    fixture.componentInstance.clarified.subscribe((r) => results.push(r));

    const select = testid('clarify-project') as HTMLSelectElement;
    select.value = 'proj-1';
    select.dispatchEvent(new Event('change'));
    testid('clarify-energy-high')?.click();
    const due = testid('clarify-due') as HTMLInputElement;
    due.value = '2026-06-12';
    due.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    testid('clarify-submit')?.click();
    expect(results).toEqual([
      { project_id: 'proj-1', energy: 'high', due: '2026-06-12' },
    ]);
  });

  it('should default to no project, medium energy, and no due date', async () => {
    await render();
    const results: ClarifyResult[] = [];
    fixture.componentInstance.clarified.subscribe((r) => results.push(r));

    testid('clarify-submit')?.click();
    expect(results).toEqual([
      { project_id: null, energy: 'medium', due: null },
    ]);
  });

  it('should emit deferInstead and closed from the footer actions', async () => {
    await render();
    let deferred = 0;
    let closed = 0;
    fixture.componentInstance.deferInstead.subscribe(() => deferred++);
    fixture.componentInstance.closed.subscribe(() => closed++);

    testid('clarify-defer-instead')?.click();
    testid('clarify-cancel')?.click();
    expect(deferred).toBe(1);
    expect(closed).toBe(1);
  });

  it('should degrade to only the default option without throwing when the projects read fails', async () => {
    fixture = TestBed.createComponent(ClarifyModalComponent);
    fixture.componentRef.setInput('item', capture);
    fixture.detectChanges();
    // Fail the projects read. projects() must fall back to [] via the
    // hasValue() guard rather than throw a ResourceValueError, leaving only
    // the "(no project)" option and a still-usable modal.
    httpMock
      .expectOne((r) => r.url.includes(PROJECTS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    const host = fixture.nativeElement as HTMLElement;
    expect(host.textContent).toContain('Research pgvector indexing');
    const select = testid('clarify-project') as HTMLSelectElement;
    expect(select.options).toHaveLength(1);
    expect(select.options[0].textContent).toContain('(no project)');
  });
});
