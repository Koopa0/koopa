import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { ProposalsTriagePageComponent } from './proposals-triage.page';
import type {
  ProposalsResponse,
  ProposedArea,
  ProposedGoal,
  ProposedProject,
} from '../../../core/services/proposal.service';

const PROPOSALS_URL = '/api/admin/commitment/proposals';
const goalActivate = (id: string) =>
  `/api/admin/commitment/goals/${id}/activate`;
const areaActivate = (id: string) =>
  `/api/admin/commitment/areas/${id}/activate`;
const areaProposed = (id: string) =>
  `/api/admin/commitment/areas/${id}/proposed`;

function area(over: Partial<ProposedArea> = {}): ProposedArea {
  return {
    id: 'ar-1',
    slug: 'health',
    name: 'Health',
    description: 'Body upkeep',
    created_by: 'planner',
    created_at: '2026-06-18T00:00:00Z',
    ...over,
  };
}

function goal(over: Partial<ProposedGoal> = {}): ProposedGoal {
  return {
    id: 'gl-1',
    title: 'Learn Go generics',
    description: 'deep dive',
    area_name: 'Build',
    created_by: 'planner',
    created_at: '2026-06-18T00:00:00Z',
    milestone_total: 0,
    ...over,
  };
}

function project(over: Partial<ProposedProject> = {}): ProposedProject {
  return {
    id: 'pr-1',
    slug: 'koopa-cli',
    title: 'Build koopa CLI',
    description: 'A command-line companion',
    created_by: 'planner',
    created_at: '2026-06-18T00:00:00Z',
    ...over,
  };
}

function payload(over: Partial<ProposalsResponse> = {}): ProposalsResponse {
  return { areas: [], goals: [], projects: [], ...over };
}

describe('ProposalsTriagePageComponent', () => {
  let fixture: ComponentFixture<ProposalsTriagePageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ProposalsTriagePageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ProposalsTriagePageComponent);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushList(body: ProposalsResponse): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(PROPOSALS_URL))
      .flush({ data: body });
  }

  async function render(body: ProposalsResponse): Promise<void> {
    await settle();
    flushList(body);
    await settle();
  }

  it('should render every pending proposal grouped under its type section', async () => {
    await render(
      payload({
        areas: [area({ id: 'ar-1', name: 'Health' }), area({ id: 'ar-2', name: 'Finance' })],
        goals: [goal({ id: 'gl-1', title: 'Learn Go generics' })],
        projects: [project({ id: 'pr-1', title: 'Build koopa CLI' })],
      }),
    );

    // Section headers carry the per-type count.
    expect(testid('proposals-section-areas')?.textContent).toContain('AREAS · 2');
    expect(testid('proposals-section-goals')?.textContent).toContain('GOALS · 1');
    expect(testid('proposals-section-projects')?.textContent).toContain(
      'PROJECTS · 1',
    );

    // All four rows land under the right section.
    expect(testid('proposals-area-row-ar-1')?.textContent).toContain('Health');
    expect(testid('proposals-area-row-ar-2')?.textContent).toContain('Finance');
    expect(testid('proposals-goal-row-gl-1')?.textContent).toContain(
      'Learn Go generics',
    );
    expect(testid('proposals-project-row-pr-1')?.textContent).toContain(
      'Build koopa CLI',
    );
  });

  it('should show each row its own proposal rationale', async () => {
    await render(
      payload({
        areas: [
          area({ id: 'ar-1', proposal_rationale: 'You logged three runs last week.' }),
        ],
        goals: [
          goal({ id: 'gl-1', proposal_rationale: 'Generics keep coming up in your reading.' }),
        ],
        projects: [
          project({ id: 'pr-1', proposal_rationale: 'You keep scripting admin calls by hand.' }),
        ],
      }),
    );

    expect(testid('proposals-area-row-ar-1')?.textContent).toContain(
      'You logged three runs last week.',
    );
    expect(testid('proposals-goal-row-gl-1')?.textContent).toContain(
      'Generics keep coming up in your reading.',
    );
    expect(testid('proposals-project-row-pr-1')?.textContent).toContain(
      'You keep scripting admin calls by hand.',
    );
  });

  it('should accept a goal in place — activate it, drop its row, keep the rest, no refetch', async () => {
    await render(
      payload({
        goals: [
          goal({ id: 'gl-1', title: 'Learn Go generics' }),
          goal({ id: 'gl-2', title: 'Read SICP' }),
        ],
        projects: [project({ id: 'pr-1' })],
      }),
    );

    testid('proposals-goal-accept-gl-1')?.click();
    await settle();

    httpMock
      .expectOne((r) => r.method === 'POST' && r.url.endsWith(goalActivate('gl-1')))
      .flush({});
    await settle();

    // The accepted row is gone; the others stay; the list was NOT refetched.
    expect(testid('proposals-goal-row-gl-1')).toBeNull();
    expect(testid('proposals-goal-row-gl-2')).toBeTruthy();
    expect(testid('proposals-project-row-pr-1')).toBeTruthy();
    httpMock.expectNone((r) => r.method === 'GET' && r.url.endsWith(PROPOSALS_URL));
  });

  it('should accept an area in place and resurface its still-proposed child goals as goal rows', async () => {
    await render(
      payload({
        areas: [area({ id: 'ar-1', name: 'Health' })],
        goals: [
          goal({ id: 'gl-1', title: 'Run 5k', area_id: 'ar-1', area_name: 'Health' }),
        ],
      }),
    );

    // The child goal renders inside the area bundle, not as a standalone row yet.
    expect(testid('proposals-area-row-ar-1')?.textContent).toContain('Run 5k');
    expect(testid('proposals-goal-row-gl-1')).toBeNull();

    testid('proposals-area-accept-ar-1')?.click();
    await settle();

    httpMock
      .expectOne((r) => r.method === 'POST' && r.url.endsWith(areaActivate('ar-1')))
      .flush({});
    await settle();

    // Area-only: the goal was never activated, the bundle is gone, and the
    // still-proposed child resurfaces as a standalone goal row — no refetch.
    httpMock.expectNone((r) => r.url.endsWith(goalActivate('gl-1')));
    expect(testid('proposals-area-row-ar-1')).toBeNull();
    expect(testid('proposals-goal-row-gl-1')?.textContent).toContain('Run 5k');
    httpMock.expectNone((r) => r.method === 'GET' && r.url.endsWith(PROPOSALS_URL));
  });

  it('should reject an area only after confirming the cascade in the dialog', async () => {
    await render(
      payload({
        areas: [area({ id: 'ar-1', name: 'Health' })],
        goals: [
          goal({ id: 'gl-1', title: 'Run 5k', area_id: 'ar-1', area_name: 'Health' }),
          goal({ id: 'gl-2', title: 'Sleep 8h', area_id: 'ar-1', area_name: 'Health' }),
        ],
      }),
    );

    testid('proposals-area-reject-ar-1')?.click();
    await settle();

    // The dialog spells out the cascade; nothing is deleted on open alone.
    expect(testid('proposals-reject-body')?.textContent).toContain(
      'This also rejects 2 proposed goals under it.',
    );

    testid('proposals-reject-confirm')?.click();
    await settle();

    httpMock
      .expectOne(
        (r) => r.method === 'DELETE' && r.url.endsWith(areaProposed('ar-1')),
      )
      .flush(null, { status: 204, statusText: 'No Content' });
    await settle();

    expect(testid('proposals-reject-body')).toBeNull();
    expect(testid('proposals-area-row-ar-1')).toBeNull();
  });

  it('should cancel an area reject without deleting anything and keep the row', async () => {
    await render(
      payload({
        areas: [area({ id: 'ar-1', name: 'Health' })],
        goals: [
          goal({ id: 'gl-1', title: 'Run 5k', area_id: 'ar-1', area_name: 'Health' }),
        ],
      }),
    );

    testid('proposals-area-reject-ar-1')?.click();
    await settle();
    expect(testid('proposals-reject-body')).toBeTruthy();

    testid('proposals-reject-cancel')?.click();
    await settle();

    // Dialog closed, area still here — and afterEach httpMock.verify() asserts
    // no DELETE was ever issued.
    expect(testid('proposals-reject-body')).toBeNull();
    expect(testid('proposals-area-row-ar-1')?.textContent).toContain('Health');
  });

  it('should show the empty state and no sections when nothing is pending', async () => {
    await render(payload());

    expect(testid('proposals-empty')?.textContent).toContain(
      'No proposals awaiting review.',
    );
    expect(testid('proposals-section-areas')).toBeNull();
    expect(testid('proposals-section-goals')).toBeNull();
    expect(testid('proposals-section-projects')).toBeNull();
  });

  it('should show the error state without throwing when the load fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(PROPOSALS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    // hasValue() guards the read, so the error state renders rather than the
    // resource throwing on value().
    expect(testid('proposals-error')).toBeTruthy();
    expect(testid('proposals-empty')).toBeNull();
    expect(testid('proposals-section-areas')).toBeNull();
  });
});
