import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { InspectorPanelComponent } from './inspector-panel.component';
import { InspectorService } from './inspector.service';
import type { GoalDetail, ProjectDetail } from '../../core/models/admin.model';

const MIN_GOAL: GoalDetail = {
  id: 'g1',
  title: 'mock',
  description: '',
  status: 'in_progress',
  area_id: 'a',
  area_name: 'backend',
  deadline: null,
  quarter: '2026-Q2',
  created_at: '2026-01-01T00:00:00Z',
  health: 'on-track',
  milestones: [],
  projects: [],
  recent_activity: [],
};

const MIN_PROJECT: ProjectDetail = {
  id: 'p1',
  title: 'mock',
  slug: 'mock',
  description: '',
  problem: null,
  solution: null,
  architecture: null,
  status: 'in_progress',
  area: 'backend',
  goal_breadcrumb: null,
  todos_by_state: {
    in_progress: [],
    todo: [],
    done: [],
    someday: [],
  },
  recent_activity: [],
  related_content: [],
};

describe('InspectorPanelComponent', () => {
  let fixture: ComponentFixture<InspectorPanelComponent>;
  let inspector: InspectorService;
  let httpMock: HttpTestingController;

  afterAll(() => TestBed.resetTestingModule());

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        provideNoopAnimations(),
      ],
    });
    fixture = TestBed.createComponent(InspectorPanelComponent);
    inspector = TestBed.inject(InspectorService);
    httpMock = TestBed.inject(HttpTestingController);
  }

  /** Drain any HTTP fired by a mounted renderer; the panel test does not
   *  care about renderer content but still needs valid shapes so the
   *  child template doesn't crash on `.length` reads. */
  function drainAllRequests(): void {
    httpMock
      .match(() => true)
      .forEach((r) => {
        if (r.request.url.includes('/goals/')) {
          r.flush(MIN_GOAL);
        } else if (r.request.url.includes('/projects/')) {
          r.flush(MIN_PROJECT);
        } else {
          r.flush({});
        }
      });
  }

  it('should not render the panel when no target is set', () => {
    setupFixture();
    fixture.detectChanges();

    const panel = fixture.nativeElement.querySelector(
      '[data-testid="inspector-panel"]',
    );
    expect(panel).toBeNull();
  });

  it('should render the panel when a goal target is set', async () => {
    setupFixture();
    inspector.syncFromUrl('goal:g1');
    fixture.detectChanges();
    drainAllRequests();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const panel = fixture.nativeElement.querySelector(
      '[data-testid="inspector-panel"]',
    );
    expect(panel).toBeTruthy();

    const typeEl = fixture.nativeElement.querySelector(
      '[data-testid="inspector-type"]',
    ) as HTMLElement;
    expect(typeEl.textContent?.trim()).toBe('Goal');
  });

  it('should render the panel when a project target is set', async () => {
    setupFixture();
    inspector.syncFromUrl('project:p1');
    fixture.detectChanges();
    drainAllRequests();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const typeEl = fixture.nativeElement.querySelector(
      '[data-testid="inspector-type"]',
    ) as HTMLElement;
    expect(typeEl.textContent?.trim()).toBe('Project');
  });

  it('should call inspector.close() when close button is clicked', async () => {
    setupFixture();
    inspector.syncFromUrl('goal:g1');
    fixture.detectChanges();
    drainAllRequests();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const closeSpy = vi.spyOn(inspector, 'close');
    const closeBtn = fixture.nativeElement.querySelector(
      '[data-testid="inspector-close"]',
    ) as HTMLButtonElement;
    closeBtn.click();

    expect(closeSpy).toHaveBeenCalled();
  });

  it('should close inspector on Escape key', async () => {
    setupFixture();
    inspector.syncFromUrl('goal:g1');
    fixture.detectChanges();
    drainAllRequests();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const closeSpy = vi.spyOn(inspector, 'close');

    const event = new KeyboardEvent('keydown', { key: 'Escape' });
    document.dispatchEvent(event);

    expect(closeSpy).toHaveBeenCalled();
  });

  it('should not intercept Escape when focus is in an input', async () => {
    setupFixture();
    inspector.syncFromUrl('goal:g1');
    fixture.detectChanges();
    drainAllRequests();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const closeSpy = vi.spyOn(inspector, 'close');

    const input = document.createElement('input');
    document.body.appendChild(input);
    input.focus();
    const event = new KeyboardEvent('keydown', {
      key: 'Escape',
      bubbles: true,
    });
    input.dispatchEvent(event);
    document.body.removeChild(input);

    expect(closeSpy).not.toHaveBeenCalled();
  });
});
