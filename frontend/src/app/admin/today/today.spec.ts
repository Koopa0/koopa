import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { By } from '@angular/platform-browser';
import { of } from 'rxjs';
import { TodayComponent } from './today';
import { TodayService } from '../../core/services/today.service';
import type { MyDayContext } from '../../core/models/admin.model';

const MOCK_CONTEXT: MyDayContext = {
  date: '2026-04-08',
  context_line: '距離 GDE 申請還有 47 天',
  yesterday_unfinished: [
    {
      id: 'dpi-y01',
      task_id: 'task-098',
      title: 'Unfinished task A',
      area: 'backend',
      energy: 'medium',
      estimated_minutes: 30,
      position: 1,
      status: 'planned',
      planned_date: '2026-04-07',
    },
    {
      id: 'dpi-y02',
      task_id: 'task-099',
      title: 'Unfinished task B',
      area: 'frontend',
      energy: 'high',
      estimated_minutes: 60,
      position: 2,
      status: 'planned',
      planned_date: '2026-04-07',
    },
  ],
  today_plan: [
    {
      id: 'dpi-001',
      task_id: 'task-101',
      title: 'Plan item 1',
      area: 'backend',
      energy: 'high',
      estimated_minutes: 90,
      position: 1,
      status: 'planned',
      planned_date: '2026-04-08',
    },
    {
      id: 'dpi-002',
      task_id: 'task-102',
      title: 'Plan item 2 (done)',
      area: 'frontend',
      energy: 'medium',
      estimated_minutes: 45,
      position: 2,
      status: 'done',
      planned_date: '2026-04-08',
    },
  ],
  overdue_tasks: [
    {
      id: 'task-090',
      title: 'Overdue task',
      due: '2026-04-05',
      area: 'backend',
      priority: 'high',
    },
  ],
  needs_attention: {
    inbox_count: 4,
    pending_directives: 1,
    unread_reports: 0,
    due_reviews: 3,
    overdue_tasks: 1,
  },
  goal_pulse: [
    {
      id: 'goal-001',
      title: 'Ship v1',
      area: 'backend',
      deadline: '2026-06-30',
      days_remaining: 83,
      milestones_total: 4,
      milestones_done: 2,
      next_milestone: 'Admin redesign',
      status: 'in-progress',
    },
  ],
};

describe('TodayComponent', () => {
  let component: TodayComponent;
  let fixture: ComponentFixture<TodayComponent>;
  let todayService: {
    getMyDayContext: ReturnType<typeof vi.fn>;
    resolveDailyItem: ReturnType<typeof vi.fn>;
  };

  beforeEach(async () => {
    todayService = {
      getMyDayContext: vi.fn().mockReturnValue(of(MOCK_CONTEXT)),
      resolveDailyItem: vi.fn().mockReturnValue(of(undefined)),
    };

    await TestBed.configureTestingModule({
      imports: [TodayComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        { provide: TodayService, useValue: todayService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(TodayComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should render today content after loading', () => {
    const content = fixture.debugElement.query(
      By.css('[data-testid="today-content"]'),
    );
    expect(content).toBeTruthy();
  });

  it('should display context line', () => {
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('距離 GDE 申請還有 47 天');
  });

  it('should show overdue banner when overdue tasks exist', () => {
    const banner = fixture.debugElement.query(
      By.css('[data-testid="overdue-banner"]'),
    );
    expect(banner).toBeTruthy();
    expect(banner.nativeElement.textContent).toContain('逾期');
  });

  it('should render yesterday unfinished items', () => {
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="unfinished-item"]'),
    );
    expect(items.length).toBe(2);
    expect(items[0].nativeElement.textContent).toContain('Unfinished task A');
  });

  it('should remove unfinished item when deferred', () => {
    const deferBtns = fixture.debugElement.queryAll(
      By.css('[data-testid="defer-btn"]'),
    );
    expect(deferBtns.length).toBe(2);

    deferBtns[0].nativeElement.click();
    fixture.detectChanges();

    expect(todayService.resolveDailyItem).toHaveBeenCalledWith(
      'dpi-y01',
      'defer',
    );

    const remaining = fixture.debugElement.queryAll(
      By.css('[data-testid="unfinished-item"]'),
    );
    expect(remaining.length).toBe(1);
  });

  it('should remove unfinished item when dropped', () => {
    const dropBtns = fixture.debugElement.queryAll(
      By.css('[data-testid="drop-btn"]'),
    );
    dropBtns[1].nativeElement.click();
    fixture.detectChanges();

    expect(todayService.resolveDailyItem).toHaveBeenCalledWith(
      'dpi-y02',
      'drop',
    );
  });

  it('should render today plan items', () => {
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="plan-item"]'),
    );
    expect(items.length).toBe(2);
  });

  it('should mark plan item as done when completed', () => {
    const completeBtns = fixture.debugElement.queryAll(
      By.css('[data-testid="plan-complete-btn"]'),
    );
    completeBtns[0].nativeElement.click();
    fixture.detectChanges();

    expect(todayService.resolveDailyItem).toHaveBeenCalledWith(
      'dpi-001',
      'complete',
    );
  });

  it('should compute total planned minutes', () => {
    const el = fixture.nativeElement as HTMLElement;
    // 90 + 45 = 135
    expect(el.textContent).toContain('135 min');
  });

  it('should show needs attention counts', () => {
    const section = fixture.debugElement.query(
      By.css('[data-testid="needs-attention"]'),
    );
    expect(section).toBeTruthy();
    expect(section.nativeElement.textContent).toContain('4');
    expect(section.nativeElement.textContent).toContain('未澄清 inbox');
  });

  it('should render goal pulse with progress', () => {
    const section = fixture.debugElement.query(
      By.css('[data-testid="goal-pulse"]'),
    );
    expect(section).toBeTruthy();
    expect(section.nativeElement.textContent).toContain('Ship v1');
    expect(section.nativeElement.textContent).toContain('2/4');
  });

  describe('when context has no unfinished or overdue', () => {
    beforeEach(() => {
      const cleanContext: MyDayContext = {
        ...MOCK_CONTEXT,
        yesterday_unfinished: [],
        overdue_tasks: [],
        needs_attention: {
          inbox_count: 0,
          pending_directives: 0,
          unread_reports: 0,
          due_reviews: 0,
          overdue_tasks: 0,
        },
      };
      todayService.getMyDayContext.mockReturnValue(of(cleanContext));
      fixture = TestBed.createComponent(TodayComponent);
      fixture.detectChanges();
    });

    it('should not show overdue banner', () => {
      const banner = fixture.debugElement.query(
        By.css('[data-testid="overdue-banner"]'),
      );
      expect(banner).toBeFalsy();
    });

    it('should not show unfinished section', () => {
      const items = fixture.debugElement.queryAll(
        By.css('[data-testid="unfinished-item"]'),
      );
      expect(items.length).toBe(0);
    });

    it('should not show needs attention when all counts are zero', () => {
      const section = fixture.debugElement.query(
        By.css('[data-testid="needs-attention"]'),
      );
      expect(section).toBeFalsy();
    });
  });

  describe('when today plan is empty', () => {
    beforeEach(() => {
      const emptyPlan: MyDayContext = {
        ...MOCK_CONTEXT,
        today_plan: [],
      };
      todayService.getMyDayContext.mockReturnValue(of(emptyPlan));
      fixture = TestBed.createComponent(TodayComponent);
      fixture.detectChanges();
    });

    it('should show empty plan state with link to tasks', () => {
      const empty = fixture.debugElement.query(
        By.css('[data-testid="empty-plan"]'),
      );
      expect(empty).toBeTruthy();
      expect(empty.nativeElement.textContent).toContain('尚未規劃');
    });
  });
});
