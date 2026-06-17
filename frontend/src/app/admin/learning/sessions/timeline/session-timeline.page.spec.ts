import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import {
  ActivatedRoute,
  convertToParamMap,
  provideRouter,
} from '@angular/router';
import { of } from 'rxjs';

import { SessionTimelinePageComponent } from './session-timeline.page';
import type { SessionDetail } from '../../../../core/models/learning.model';

// Wire-contract guard. Ground truth: internal/learning/handler.go
// ::SessionDetailResponse = { session: Session, attempts: Attempt[] }. The
// endpoint ships NO summary block and NO reflection note — the page derives
// the completion metrics from `attempts`. This spec mocks the HTTP boundary.

const SESSION_URL = '/api/admin/learning/sessions/s1';

function detail(): SessionDetail {
  return {
    session: {
      id: 's1',
      domain: 'go',
      mode: 'practice',
      started_at: '2026-06-16T09:00:00Z',
      ended_at: '2026-06-16T10:00:00Z',
      created_at: '2026-06-16T09:00:00Z',
    },
    attempts: [
      {
        id: 'a1',
        learning_target_id: 't1',
        session_id: 's1',
        attempt_number: 1,
        paradigm: 'recall',
        outcome: 'solved_independent',
        attempted_at: '2026-06-16T09:10:00Z',
        approach_used: 'value receiver',
        target_title: 'Value vs pointer receivers',
        observations: [
          {
            id: 'o1',
            attempt_id: 'a1',
            concept_id: 'c1',
            signal_type: 'weakness',
            category: 'semantics',
            confidence: 'high',
            position: 0,
            concept_slug: 'receivers',
            detail: 'reached for a pointer receiver first',
          },
        ],
      },
      {
        id: 'a2',
        learning_target_id: 't2',
        session_id: 's1',
        attempt_number: 2,
        paradigm: 'apply',
        outcome: 'solved_independent',
        attempted_at: '2026-06-16T09:30:00Z',
        target_title: 'Slice aliasing',
        // observations omitted on the wire (omitempty) — must not crash.
      },
      {
        id: 'a3',
        learning_target_id: 't3',
        session_id: 's1',
        attempt_number: 3,
        paradigm: 'apply',
        outcome: 'solved_with_hint',
        attempted_at: '2026-06-16T09:50:00Z',
        target_title: 'Channel direction',
      },
    ],
  };
}

describe('SessionTimelinePageComponent', () => {
  let fixture: ComponentFixture<SessionTimelinePageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SessionTimelinePageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 's1' })) },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    try {
      flushSession(detail());
      httpMock.verify();
    } finally {
      TestBed.resetTestingModule();
    }
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  function flushSession(body: SessionDetail): number {
    const reqs = httpMock.match(
      (r) => r.method === 'GET' && r.url.endsWith(SESSION_URL),
    );
    for (const r of reqs) r.flush({ data: body });
    return reqs.length;
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function render(body: SessionDetail): Promise<void> {
    fixture = TestBed.createComponent(SessionTimelinePageComponent);
    fixture.detectChanges();
    expect(flushSession(body)).toBeGreaterThan(0);
    await settle();
    flushSession(body);
    fixture.detectChanges();
  }

  it('should render session metadata + attempts from the {session, attempts} wire', async () => {
    await render(detail());

    expect(testid('session-hero')?.textContent).toContain('go');
    expect(testid('session-hero')?.textContent).toContain('practice');
    const attempts = testid('session-attempts');
    expect(attempts?.textContent).toContain('Value vs pointer receivers');
    expect(attempts?.textContent).toContain('Channel direction');
  });

  it('should derive the summary client-side from attempts (no summary on the wire)', async () => {
    await render(detail());

    // 3 attempts, 2 solved-independent, 1 solved-with-hint → 67% rate.
    const summary = testid('session-summary');
    expect(summary?.textContent).toContain('67%');
    expect(summary?.textContent).toContain('Solved independent');
  });

  it('should render observation fields from the wire and tolerate attempts with none', async () => {
    await render(detail());

    const attempts = testid('session-attempts');
    expect(attempts?.textContent).toContain('weakness'); // signal_type
    expect(attempts?.textContent).toContain('reached for a pointer receiver first'); // detail
    expect(attempts?.textContent).toContain('receivers'); // concept_slug
    // The attempt with no observations rendered without crashing.
    expect(attempts?.textContent).toContain('Slice aliasing');
  });
});
