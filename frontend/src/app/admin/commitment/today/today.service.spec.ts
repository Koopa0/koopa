import { vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';

import { TodayService, type TodayVm } from './today.service';
import { ContentService } from '../../../core/services/content.service';
import { HypothesisService } from '../../../core/services/hypothesis.service';
import { TaskService } from '../../../core/services/task.service';
import { DailyPlanService } from '../../../core/services/daily-plan.service';
import { SystemService } from '../../../core/services/system.service';

// Track 1B — Today fan-out contract test.
//
// Pins the CURRENT canonical Today behavior: frontend fan-out composition in
// TodayService.today(). The backend aggregate /api/admin/commitment/today is
// NOT under test here (Track 1A reconciliation: future target, not current
// contract).
//
// Fixed clock: 2026-05-21T04:00:00Z == 12:00 Asia/Taipei. Chosen far from both
// UTC midnight and Taipei midnight (16:00Z), so todayIso() (UTC-date derived)
// and daysSince() (UTC-ms math) are deterministic regardless of the runner's
// local timezone. No assertion depends on wall-clock now.
const FIXED_NOW = new Date('2026-05-21T04:00:00Z');

// Fixture timestamps, all at 04:00Z so daysSince() yields whole days from
// FIXED_NOW with no boundary ambiguity.
const CONTENT_UPDATED_AT = '2026-05-20T04:00:00Z'; // 1 day before now
const TASK_COMPLETED_AT = '2026-05-19T04:00:00Z'; // 2 days before now
const HYP_CREATED_AT = '2026-05-18T04:00:00Z'; // 3 days before now

interface FanoutMocks {
  reviewContent: unknown[];
  hypotheses: unknown[];
  completedTasks: unknown[];
  plan: unknown;
  health: unknown;
}

function happyFixtures(): FanoutMocks {
  return {
    reviewContent: [
      {
        id: 'c1',
        title: 'Value semantics in Go',
        type: 'article',
        updated_at: CONTENT_UPDATED_AT,
        reading_time_min: 7,
      },
    ],
    hypotheses: [
      {
        id: 'h1',
        claim: 'DFS termination is my weak spot',
        created_at: HYP_CREATED_AT,
        created_by: 'learning-studio',
      },
    ],
    completedTasks: [
      {
        id: 't1',
        title: 'Industry scan Q2',
        source: 'hq',
        target: 'research-lab',
        submitted_at: '2026-05-17T04:00:00Z',
        completed_at: TASK_COMPLETED_AT,
      },
    ],
    // Backend-realistic daily-plan items: the real /daily-plan wire shape is
    // {id, todo_id, title, state, selected_by, …} — NOT the legacy
    // {todo_title, todo_state, status, position} model. A fictional `{id:'p1'}`
    // would map to {title:undefined, status:undefined} and fail the assertion.
    plan: {
      date: '2026-05-21',
      items: [
        { id: 'p1', todo_id: 'td1', title: 'Fix auth middleware', state: 'planned', selected_by: 'hq' },
        { id: 'p2', todo_id: 'td2', title: 'Ship release notes', state: 'done', selected_by: 'hq' },
      ],
      total: 2,
      done: 1,
      overdue_count: 1,
    },
    health: {
      feeds: { failing_feeds: [{ name: 'Go Blog', error: 'timeout' }] },
      pipelines: { failed: 2 },
      database: {},
    },
  };
}

// configure wires loosely-typed mocks (useValue is untyped at the provider
// boundary) so each fan-out source can be set to data, empty, or an error
// observable independently. `error` keys force that single source to throw.
function configure(
  fx: FanoutMocks,
  errors: Partial<Record<keyof FanoutMocks, boolean>> = {},
): TodayService {
  const src = <T>(key: keyof FanoutMocks, value: T) =>
    errors[key] ? throwError(() => new Error(`${String(key)} failed`)) : of(value);

  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      TodayService,
      { provide: ContentService, useValue: { adminList: () => src('reviewContent', { data: fx.reviewContent }) } },
      { provide: HypothesisService, useValue: { list: () => src('hypotheses', fx.hypotheses) } },
      { provide: TaskService, useValue: { completed: () => src('completedTasks', fx.completedTasks) } },
      { provide: DailyPlanService, useValue: { today: () => src('plan', fx.plan) } },
      { provide: SystemService, useValue: { getHealth: () => src('health', fx.health) } },
    ],
  });
  return TestBed.inject(TodayService);
}

describe('TodayService.today() — fan-out composition', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('composes the four Today regions from all five sources', async () => {
    const service = configure(happyFixtures());
    const vm = await firstValue(service);

    expect(vm.date).toBe('2026-05-21');

    // Plan: backend-realistic items map to the Today view-model {id,title,status}
    // (title ← backend `title`, status ← backend `state`). Fictional `{id:'p1'}`
    // items would produce title/status undefined and fail this assertion.
    expect(vm.plan).toEqual({
      date: '2026-05-21',
      items: [
        { id: 'p1', title: 'Fix auth middleware', status: 'planned' },
        { id: 'p2', title: 'Ship release notes', status: 'done' },
      ],
      total: 2,
      done: 1,
      overdue: 1,
    });

    // Warnings: feed (warn) + pipeline (error) — the CURRENT fan-out sources.
    expect(vm.warnings).toEqual([
      { severity: 'warn', source: 'feed', message: 'Go Blog failing — timeout' },
      { severity: 'error', source: 'pipeline', message: '2 pipeline runs failed in the last 24h' },
    ]);
  });

  it('sorts awaiting-judgment ascending by submittedAt and decorates each kind', async () => {
    const service = configure(happyFixtures());
    const vm = await firstValue(service);

    // Ascending by submittedAt: hypothesis(05-18) < task(completed 05-19) < content(05-20).
    expect(vm.awaitingJudgment.map((r) => r.id)).toEqual(['h1', 't1', 'c1']);
    expect(vm.awaitingJudgment.map((r) => r.kind)).toEqual(['hypothesis', 'task', 'content']);
    expect(vm.awaitingJudgment.map((r) => r.badge)).toEqual(['HYP', 'TSK', 'ART']);

    const [hyp, task, content] = vm.awaitingJudgment;
    // Deterministic ages from the fixed clock (no wall-clock dependency).
    expect([hyp.ageDays, task.ageDays, content.ageDays]).toEqual([3, 2, 1]);
    // Only content is routable in the current product contract.
    expect(content.route).toBe('/admin/knowledge/content/c1/edit');
    expect(hyp.route).toBeNull();
    expect(task.route).toBeNull();
    // Task subtitle reflects source → target.
    expect(task.subtitle).toBe('hq → research-lab · completed');
    expect(content.subtitle).toBe('article · 7 min read');
  });

  it('renders empty regions when every source is empty (no crash)', async () => {
    const service = configure({
      reviewContent: [],
      hypotheses: [],
      completedTasks: [],
      plan: { date: '2026-05-21', items: [], total: 0, done: 0, overdue_count: 0 },
      health: { feeds: { failing_feeds: [] }, pipelines: { failed: 0 }, database: {} },
    });
    const vm = await firstValue(service);

    expect(vm.awaitingJudgment).toEqual([]);
    expect(vm.warnings).toEqual([]);
    expect(vm.plan?.items).toEqual([]);
    expect(vm.plan?.total).toBe(0);
  });

  // Per-source degradation across all five fan-out sources. (TodayService has
  // NO open/active-task source — the only task source is `completed`, covered
  // by the completedTasks case — so that bullet is N/A by current design.)
  // Each case asserts the failing slice degrades AND a surviving region is
  // still populated, proving one failure never crashes the whole Today VM.
  const degradationCases: readonly {
    source: keyof FanoutMocks;
    assert: (vm: TodayVm) => void;
  }[] = [
    {
      source: 'reviewContent',
      assert: (vm) => {
        expect(vm.awaitingJudgment.map((r) => r.kind)).toEqual(['hypothesis', 'task']);
        expect(vm.plan).not.toBeNull(); // survivor
      },
    },
    {
      source: 'hypotheses',
      assert: (vm) => {
        expect(vm.awaitingJudgment.map((r) => r.kind)).toEqual(['task', 'content']);
        expect(vm.plan).not.toBeNull();
      },
    },
    {
      source: 'completedTasks',
      assert: (vm) => {
        expect(vm.awaitingJudgment.map((r) => r.kind)).toEqual(['hypothesis', 'content']);
        expect(vm.warnings).toHaveLength(2);
      },
    },
    {
      source: 'plan',
      assert: (vm) => {
        expect(vm.plan).toBeNull();
        expect(vm.awaitingJudgment).toHaveLength(3); // survivor
      },
    },
    {
      source: 'health',
      assert: (vm) => {
        expect(vm.warnings).toEqual([]);
        expect(vm.awaitingJudgment).toHaveLength(3);
      },
    },
  ];

  it.each(degradationCases)(
    'degrades only the $source slice when it fails, without crashing the whole Today VM',
    async ({ source, assert }) => {
      const vm = await firstValue(configure(happyFixtures(), { [source]: true }));
      expect(vm.date).toBe('2026-05-21'); // VM still emitted
      assert(vm);
    },
  );
});

// firstValue resolves the single emission of today() — a cold one-shot
// combineLatest that completes after one value.
function firstValue(service: TodayService): Promise<TodayVm> {
  return new Promise<TodayVm>((resolve, reject) => {
    service.today().subscribe({ next: resolve, error: reject });
  });
}
