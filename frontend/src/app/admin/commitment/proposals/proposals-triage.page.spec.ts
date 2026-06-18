import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { ProposalsTriagePageComponent } from './proposals-triage.page';
import type { ProposalsResponse } from '../../../core/services/proposal.service';

const PROPOSALS_URL = '/api/admin/commitment/proposals';
const goalActivate = (id: string) =>
  `/api/admin/commitment/goals/${id}/activate`;
const areaActivate = (id: string) =>
  `/api/admin/commitment/areas/${id}/activate`;
const goalProposed = (id: string) =>
  `/api/admin/commitment/goals/${id}/proposed`;
const areaProposed = (id: string) =>
  `/api/admin/commitment/areas/${id}/proposed`;
const goalEdit = (id: string) => `/api/admin/commitment/goals/${id}`;

/** Two cards: a proposed area bundle (Health + Run 5k), then a standalone
 *  proposed goal (Learn Go generics, under an already-active area). */
function proposals(overrides: Partial<ProposalsResponse> = {}): ProposalsResponse {
  return {
    areas: [
      {
        id: 'ar-1',
        slug: 'health',
        name: 'Health',
        description: 'Body upkeep',
        created_by: 'planner',
        created_at: '2026-06-18T00:00:00Z',
      },
    ],
    goals: [
      {
        id: 'gl-1',
        title: 'Run 5k',
        description: '',
        area_id: 'ar-1',
        area_name: 'Health',
        created_by: 'planner',
        created_at: '2026-06-18T00:00:00Z',
        milestone_total: 2,
      },
      {
        id: 'gl-2',
        title: 'Learn Go generics',
        description: 'deep dive',
        area_name: 'Build',
        created_by: 'planner',
        created_at: '2026-06-18T00:00:00Z',
        milestone_total: 0,
      },
    ],
    ...overrides,
  };
}

/** A single standalone proposed goal (no proposed-area parent). */
function goalOnly(): ProposalsResponse {
  return {
    areas: [],
    goals: [
      {
        id: 'gl-2',
        title: 'Learn Go generics',
        description: 'deep dive',
        area_name: 'Build',
        created_by: 'planner',
        created_at: '2026-06-18T00:00:00Z',
        milestone_total: 0,
      },
    ],
  };
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

  function flushList(payload: ProposalsResponse): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(PROPOSALS_URL))
      .flush({ data: payload });
  }

  async function render(payload: ProposalsResponse = proposals()): Promise<void> {
    await settle();
    flushList(payload);
    await settle();
  }

  it('should show the area bundle first with its goals and the X-of-N position', async () => {
    await render();

    expect(testid('proposals-position')?.textContent).toContain('1 of 2');
    const card = testid('proposals-area-card');
    expect(card).toBeTruthy();
    expect(card?.textContent).toContain('Health');
    expect(testid('proposals-area-goals')?.textContent).toContain('Includes 1');
    expect(card?.textContent).toContain('Run 5k');
  });

  it('should activate only the area and resurface its child goal as a standalone card', async () => {
    await render();

    testid('proposals-area-activate')?.click();
    await settle();

    // Area-only: exactly the per-area activate, never a per-goal activate.
    httpMock
      .expectOne((r) => r.method === 'POST' && r.url.endsWith(areaActivate('ar-1')))
      .flush({});
    httpMock.expectNone((r) => r.url.endsWith(goalActivate('gl-1')));
    await settle();

    // The queue re-fetches; the still-proposed child comes back standalone now
    // that its parent area is active (no longer a proposed bundle).
    flushList({
      areas: [],
      goals: [
        {
          id: 'gl-1',
          title: 'Run 5k',
          description: '',
          area_id: 'ar-1',
          area_name: 'Health',
          created_by: 'planner',
          created_at: '2026-06-18T00:00:00Z',
          milestone_total: 2,
        },
        {
          id: 'gl-2',
          title: 'Learn Go generics',
          description: 'deep dive',
          area_name: 'Build',
          created_by: 'planner',
          created_at: '2026-06-18T00:00:00Z',
          milestone_total: 0,
        },
      ],
    });
    await settle();

    expect(testid('proposals-area-card')).toBeNull();
    expect(testid('proposals-goal-card')?.textContent).toContain('Run 5k');
    expect(testid('proposals-position')?.textContent).toContain('1 of 2');
  });

  it('should render the proposal rationale on the area card when present', async () => {
    await render({
      areas: [
        {
          id: 'ar-1',
          slug: 'health',
          name: 'Health',
          description: 'Body upkeep',
          created_by: 'planner',
          created_at: '2026-06-18T00:00:00Z',
          proposal_rationale: 'You logged three runs last week — worth committing to.',
        },
      ],
      goals: [],
    });

    const rationale = testid('proposals-rationale');
    expect(rationale).toBeTruthy();
    expect(rationale?.textContent).toContain(
      'You logged three runs last week',
    );
  });

  it('should render the proposal rationale on the standalone goal card when present', async () => {
    await render({
      areas: [],
      goals: [
        {
          id: 'gl-2',
          title: 'Learn Go generics',
          description: 'deep dive',
          area_name: 'Build',
          created_by: 'planner',
          created_at: '2026-06-18T00:00:00Z',
          milestone_total: 0,
          proposal_rationale: 'Generics keep coming up in your reading.',
        },
      ],
    });

    expect(testid('proposals-rationale')?.textContent).toContain(
      'Generics keep coming up',
    );
  });

  it('should omit the rationale block when none was given', async () => {
    await render(goalOnly());

    expect(testid('proposals-rationale')).toBeNull();
  });

  it('should activate a standalone goal and then show the all-clear state', async () => {
    await render(goalOnly());

    expect(testid('proposals-position')?.textContent).toContain('1 of 1');
    testid('proposals-goal-activate')?.click();
    await settle();

    httpMock
      .expectOne((r) => r.method === 'POST' && r.url.endsWith(goalActivate('gl-2')))
      .flush({});
    await settle();

    expect(testid('proposals-all-clear')).toBeTruthy();
  });

  it('should edit the title then PUT and activate when save & activate is clicked', async () => {
    await render(goalOnly());

    testid('proposals-goal-edit')?.click();
    await settle();

    const input = el().querySelector<HTMLInputElement>(
      '[data-testid="proposals-goal-edit-title"]',
    );
    expect(input?.value).toBe('Learn Go generics');
    input!.value = 'Learn Go generics deeply';
    input!.dispatchEvent(new Event('input'));
    await settle();

    testid('proposals-goal-save')?.click();
    await settle();

    const put = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(goalEdit('gl-2')),
    );
    expect(put.request.body).toEqual({ title: 'Learn Go generics deeply' });
    put.flush({ data: {} });

    httpMock
      .expectOne((r) => r.method === 'POST' && r.url.endsWith(goalActivate('gl-2')))
      .flush({});
    await settle();

    expect(testid('proposals-all-clear')).toBeTruthy();
  });

  it('should reject a standalone goal after confirmation', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await render(goalOnly());

    testid('proposals-goal-reject')?.click();
    await settle();

    expect(confirmSpy).toHaveBeenCalledWith(
      'Reject "Learn Go generics"? This permanently removes the proposed goal.',
    );
    httpMock
      .expectOne(
        (r) => r.method === 'DELETE' && r.url.endsWith(goalProposed('gl-2')),
      )
      .flush(null, { status: 204, statusText: 'No Content' });
    await settle();

    expect(testid('proposals-all-clear')).toBeTruthy();
  });

  it('should surface the goal cascade in the confirm when rejecting an area bundle', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await render();

    testid('proposals-area-reject')?.click();
    await settle();

    expect(confirmSpy).toHaveBeenCalledWith(
      'Reject "Health"? This also rejects 1 proposed goal under it.',
    );
    httpMock
      .expectOne(
        (r) => r.method === 'DELETE' && r.url.endsWith(areaProposed('ar-1')),
      )
      .flush(null, { status: 204, statusText: 'No Content' });
    await settle();

    expect(testid('proposals-position')?.textContent).toContain('2 of 2');
  });

  it('should not call the API when a reject confirmation is dismissed', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    await render(goalOnly());

    testid('proposals-goal-reject')?.click();
    await settle();
    // afterEach httpMock.verify() asserts no DELETE went out.
  });

  it('should show the empty state when there are no proposals', async () => {
    await render({ areas: [], goals: [] });

    expect(testid('proposals-empty')).toBeTruthy();
    expect(testid('proposals-area-card')).toBeNull();
    expect(testid('proposals-goal-card')).toBeNull();
  });

  it('should show the error state and re-request on retry when the load fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(PROPOSALS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(testid('proposals-error')).toBeTruthy();

    testid('proposals-retry')?.click();
    await settle();

    flushList(proposals());
    await settle();

    expect(testid('proposals-error')).toBeNull();
    expect(testid('proposals-area-card')).toBeTruthy();
  });
});
