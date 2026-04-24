import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { TodoInspectorComponent } from './todo-inspector.component';
import { InspectorService } from '../../inspector.service';
import type { TodoDetail } from '../../../../core/models/workbench.model';

const baseTodo: TodoDetail = {
  id: 't1',
  title: 'Fix auth middleware',
  state: 'in_progress',
  description: 'JWT signature verification edge case.',
  due: null,
  energy: 'medium',
  priority: 'high',
  recur_interval: null,
  recur_unit: null,
  completed_at: null,
  project_id: 'p1',
  project_title: 'Auth',
  project_slug: 'auth',
  assignee: 'human',
  created_by: 'human',
  recent_skip_count_30d: null,
  created_at: '2026-04-15T08:00:00Z',
  updated_at: '2026-04-17T09:00:00Z',
};

describe('TodoInspectorComponent', () => {
  let fixture: ComponentFixture<TodoInspectorComponent>;
  let httpMock: HttpTestingController;
  let inspector: InspectorService;

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
        provideRouter([]),
      ],
    });
    fixture = TestBed.createComponent(TodoInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
    inspector = TestBed.inject(InspectorService);
  }

  function flushAll(id: string, response: TodoDetail | null): void {
    const reqs = httpMock.match((r) =>
      r.url.includes(`/api/admin/commitment/todos/${id}`),
    );
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      if (response === null) {
        r.flush(null, { status: 500, statusText: 'Internal Server Error' });
      } else {
        r.flush({ data: response });
      }
    }
  }

  async function loadAndSettle(t: TodoDetail | null): Promise<void> {
    fixture.componentRef.setInput('id', 't1');
    fixture.detectChanges();
    flushAll('t1', t);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should render title and state as colored text (not bg pill)', async () => {
    setupFixture();
    await loadAndSettle(baseTodo);

    const el = fixture.nativeElement as HTMLElement;
    expect(
      el.querySelector('[data-testid="todo-title"]')?.textContent,
    ).toContain('Fix auth middleware');
    const stateText = el.querySelector('[data-testid="todo-state-text"]');
    expect(stateText?.textContent?.trim()).toBe('in_progress');
    // State renders as colored text, not a filled background pill.
    expect(stateText?.className).toContain('text-amber-400');
    expect(stateText?.className).not.toContain('bg-amber-900/40');

    httpMock.verify();
  });

  it('should render relative-time due as "overdue Nd" with red text when past due', async () => {
    setupFixture();
    const past = new Date();
    past.setDate(past.getDate() - 2);
    await loadAndSettle({ ...baseTodo, due: past.toISOString() });

    const due = fixture.nativeElement.querySelector('[data-testid="todo-due"]');
    expect(due?.textContent?.trim()).toContain('overdue 2d');
    expect(due?.className).toContain('text-red-400');

    httpMock.verify();
  });

  it('should render description prose when present', async () => {
    setupFixture();
    await loadAndSettle(baseTodo);
    const desc = fixture.nativeElement.querySelector(
      '[data-testid="todo-description"]',
    );
    expect(desc?.textContent).toContain('JWT signature verification');

    httpMock.verify();
  });

  it('should expose copy todo ID button with CDK Clipboard binding', async () => {
    setupFixture();
    await loadAndSettle(baseTodo);
    const copyBtn = fixture.nativeElement.querySelector(
      '[data-testid="todo-copy-id"]',
    ) as HTMLButtonElement;
    expect(copyBtn).toBeTruthy();
    expect(copyBtn.getAttribute('aria-label')).toBe(
      'Copy todo ID to clipboard',
    );

    httpMock.verify();
  });

  it('should NOT render created_by row when created_by === assignee', async () => {
    setupFixture();
    await loadAndSettle(baseTodo); // both 'human'

    const createdBy = fixture.nativeElement.querySelector(
      '[data-testid="todo-created-by"]',
    );
    expect(createdBy).toBeFalsy();

    httpMock.verify();
  });

  it('should render created_by row when created_by ≠ assignee (delegation signal)', async () => {
    setupFixture();
    await loadAndSettle({ ...baseTodo, created_by: 'hq', assignee: 'human' });

    const createdBy = fixture.nativeElement.querySelector(
      '[data-testid="todo-created-by"]',
    );
    expect(createdBy?.textContent?.trim()).toBe('hq');

    httpMock.verify();
  });

  it('should render recurrence text and append skip count when > 0', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseTodo,
      recur_interval: 2,
      recur_unit: 'weeks',
      recent_skip_count_30d: 1,
    });

    const facts = fixture.nativeElement.querySelector(
      '[data-testid="todo-facts"]',
    );
    expect(facts?.textContent).toContain('Repeats every 2 weeks');
    const skipHint = fixture.nativeElement.querySelector(
      '[data-testid="todo-skip-hint"]',
    );
    expect(skipHint?.textContent?.trim()).toBe('· 1 skipped 30d');

    httpMock.verify();
  });

  it('should NOT show skip hint when count is 0 or null', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseTodo,
      recur_interval: 2,
      recur_unit: 'weeks',
      recent_skip_count_30d: 0,
    });

    const skipHint = fixture.nativeElement.querySelector(
      '[data-testid="todo-skip-hint"]',
    );
    expect(skipHint).toBeFalsy();

    httpMock.verify();
  });

  it('should call inspector.open with type=project when project link clicked', async () => {
    setupFixture();
    const openSpy = vi.spyOn(inspector, 'open');
    await loadAndSettle(baseTodo);

    const projectLink = fixture.nativeElement.querySelector(
      '[data-testid="todo-project-link"]',
    ) as HTMLButtonElement;
    projectLink.click();

    expect(openSpy).toHaveBeenCalledWith({ type: 'project', id: 'p1' });

    httpMock.verify();
  });

  it('should render error state when fetch fails', async () => {
    setupFixture();
    await loadAndSettle(null);

    const alert = (fixture.nativeElement as HTMLElement).querySelector(
      '[role="alert"]',
    );
    expect(alert?.textContent).toContain('Failed');

    httpMock.verify();
  });
});
