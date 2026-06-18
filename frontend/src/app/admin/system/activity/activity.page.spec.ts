import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideRouter } from '@angular/router';

import { ActivityPageComponent } from './activity.page';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

// Wire-contract spec for the activity changelog. Ground truth is
// internal/activity/activity.go::ChangelogResponse + handler.go::Changelog:
// GET /api/admin/system/activity returns
//   { data: { days: [ { date, event_count, events: [ {
//     id, entity_type, entity_id?, change_kind, actor, project?, title?, timestamp
//   } ] } ] } }
// `actor` is always on the wire (non-null). The backend honors `source`
// (entity type), `project`, `actor`, `days` — there is NO change_kind
// filter param. This spec mocks the real HTTP boundary.

const CHANGELOG_WIRE = {
  data: {
    days: [
      {
        date: '2026-06-16',
        event_count: 2,
        events: [
          {
            id: '11111111-1111-1111-1111-111111111111',
            entity_type: 'content',
            entity_id: 'abc',
            change_kind: 'published',
            actor: 'planner',
            project: 'koopa',
            title: 'Value semantics in Go',
            timestamp: '2026-06-16T09:00:00Z',
          },
          {
            id: '22222222-2222-2222-2222-222222222222',
            entity_type: 'note',
            change_kind: 'created',
            actor: 'human',
            title: 'pgvector indexing notes',
            timestamp: '2026-06-16T10:30:00Z',
          },
        ],
      },
      {
        date: '2026-06-15',
        event_count: 1,
        events: [
          {
            id: '33333333-3333-3333-3333-333333333333',
            entity_type: 'todo',
            change_kind: 'completed',
            actor: 'human',
            title: 'review the PR',
            timestamp: '2026-06-15T18:00:00Z',
          },
        ],
      },
    ],
  },
};

// The activity page sources its actor filter chips from the agent registry
// (GET /api/admin/system/agents). Roster ground truth:
// internal/agent/handler.go::agentResponse (name = the `actor` filter value).
const AGENTS_WIRE = {
  data: [
    {
      name: 'planner',
      display_name: 'Planner',
      platform: 'claude-cowork',
      description: 'Daily-driver planner',
      status: 'active',
    },
    {
      name: 'human',
      display_name: 'Koopa',
      platform: 'human',
      description: 'Sole decision-maker',
      status: 'active',
    },
  ],
};

describe('ActivityPageComponent', () => {
  let fixture: ComponentFixture<ActivityPageComponent>;
  let httpMock: HttpTestingController;
  let el: HTMLElement;

  function configure(): void {
    TestBed.configureTestingModule({
      imports: [ActivityPageComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    fixture = TestBed.createComponent(ActivityPageComponent);
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    // Actor chips come from the registry — drain that read so the roster
    // (planner, human) is available to the actor filter.
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/agents'))
      .flush(AGENTS_WIRE);
  }

  async function settle(): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  }

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  it('should group events by day from the changelog wire', async () => {
    configure();
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/activity'))
      .flush(CHANGELOG_WIRE);
    await settle();

    // Two day sections, three events total (2 + 1), count chip = 3.
    const days = el.querySelectorAll('[data-testid="activity-timeline"] section');
    expect(days.length).toBe(2);
    const events = el.querySelectorAll('[data-testid^="activity-event-"]');
    expect(events.length).toBe(3);
    expect(
      el.querySelector('[data-testid="activity-count"]')?.textContent,
    ).toContain('3');
  });

  it('should render the actor that is on the wire for each event', async () => {
    configure();
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/activity'))
      .flush(CHANGELOG_WIRE);
    await settle();

    const firstEvent = el.querySelector(
      '[data-testid="activity-event-11111111-1111-1111-1111-111111111111"]',
    );
    expect(firstEvent?.textContent).toContain('planner'); // actor
    expect(firstEvent?.textContent).toContain('Value semantics in Go'); // title
    expect(firstEvent?.textContent?.toLowerCase()).toContain('content'); // entity_type
  });

  it('should pass ?source= (NOT entity_type / change_kind) when an entity filter is set', async () => {
    configure();
    // Initial unfiltered load.
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/activity'))
      .flush(CHANGELOG_WIRE);
    await settle();

    // Activate the Content entity chip.
    const contentChip = el.querySelector(
      '[data-testid="activity-filter-entity-content"]',
    ) as HTMLButtonElement | null;
    expect(contentChip).toBeTruthy();
    contentChip!.click();
    fixture.detectChanges();

    const filtered = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/system/activity'),
    );
    // Backend reads `source`; entity_type and change_kind are NOT honored.
    expect(filtered.request.params.get('source')).toBe('content');
    expect(filtered.request.params.has('entity_type')).toBe(false);
    expect(filtered.request.params.has('change_kind')).toBe(false);
    filtered.flush(CHANGELOG_WIRE);
    await settle();
  });

  it('should send ?actor= when an actor chip from the roster is selected', async () => {
    configure();
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/activity'))
      .flush(CHANGELOG_WIRE);
    await settle();

    // Chips are sourced from the registry roster flushed in configure();
    // pick the planner chip (data-testid uses the agent name).
    const plannerChip = el.querySelector(
      '[data-testid="activity-filter-actor-planner"]',
    ) as HTMLButtonElement | null;
    expect(plannerChip).toBeTruthy();
    plannerChip!.click();
    fixture.detectChanges();

    const filtered = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/system/activity'),
    );
    expect(filtered.request.params.get('actor')).toBe('planner');
    expect(filtered.request.params.has('change_kind')).toBe(false);
    filtered.flush(CHANGELOG_WIRE);
    await settle();
  });

  it('should NOT render a change-kind filter toolbar (no backend filter for it)', async () => {
    configure();
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/activity'))
      .flush(CHANGELOG_WIRE);
    await settle();

    expect(el.querySelector('[data-testid="activity-filter-kind"]')).toBeNull();
  });

  it('should show the empty state when no events are returned', async () => {
    configure();
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/activity'))
      .flush({ data: { days: [] } });
    await settle();

    expect(el.querySelector('[data-testid="activity-empty"]')).toBeTruthy();
    expect(el.textContent).toContain('No activity in this filter window.');
  });

  it('should surface the error banner without throwing when the changelog read fails', async () => {
    configure();
    // Fail the changelog read with a 500. days() must fall back to [] via the
    // hasValue() guard rather than throw a ResourceValueError, and the error
    // banner must render. (The agents roster read was drained in configure().)
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/system/activity'))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await settle();

    expect(el.querySelector('[data-testid="activity-error"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="activity-timeline"]')).toBeNull();
  });
});
