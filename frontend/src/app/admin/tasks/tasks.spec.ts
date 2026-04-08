import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { By } from '@angular/platform-browser';
import { of } from 'rxjs';
import { TasksComponent } from './tasks';
import { PlanService } from '../../core/services/plan.service';
import type { TaskBacklogItem } from '../../core/models/admin.model';

const MOCK_TASKS: TaskBacklogItem[] = [
  {
    id: 'task-1',
    title: 'Todo task A',
    status: 'todo',
    area: 'backend',
    priority: 'high',
    energy: 'high',
    due: '2026-04-10',
    project_title: 'koopa0.dev',
    is_in_today_plan: false,
  },
  {
    id: 'task-2',
    title: 'Active task B',
    status: 'in-progress',
    area: 'frontend',
    priority: 'medium',
    energy: 'medium',
    due: null,
    project_title: null,
    is_in_today_plan: true,
  },
  {
    id: 'task-3',
    title: 'Someday task C',
    status: 'someday',
    area: 'learning',
    priority: 'low',
    energy: 'low',
    due: null,
    project_title: 'LeetCode',
    is_in_today_plan: false,
  },
  {
    id: 'task-4',
    title: 'Another todo',
    status: 'todo',
    area: 'backend',
    priority: 'medium',
    energy: 'high',
    due: null,
    project_title: null,
    is_in_today_plan: false,
  },
];

describe('TasksComponent', () => {
  let fixture: ComponentFixture<TasksComponent>;
  let planService: {
    getTaskBacklog: ReturnType<typeof vi.fn>;
    advanceTask: ReturnType<typeof vi.fn>;
  };

  beforeEach(async () => {
    planService = {
      getTaskBacklog: vi
        .fn()
        .mockReturnValue(of({ tasks: MOCK_TASKS, meta: { total: 4 } })),
      advanceTask: vi.fn().mockReturnValue(of(undefined)),
    };

    await TestBed.configureTestingModule({
      imports: [TasksComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        { provide: PlanService, useValue: planService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(TasksComponent);
    fixture.detectChanges();
  });

  it('should default to todo filter and show only todo tasks', () => {
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="task-item"]'),
    );
    // default filter is 'todo', so only task-1 and task-4
    expect(items.length).toBe(2);
    expect(items[0].nativeElement.textContent).toContain('Todo task A');
    expect(items[1].nativeElement.textContent).toContain('Another todo');
  });

  it('should show all tasks when all tab selected', () => {
    const allTab = fixture.debugElement.query(
      By.css('[data-testid="tab-all"]'),
    );
    allTab.nativeElement.click();
    fixture.detectChanges();

    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="task-item"]'),
    );
    expect(items.length).toBe(4);
  });

  it('should show in-progress tasks when active tab selected', () => {
    const activeTab = fixture.debugElement.query(
      By.css('[data-testid="tab-in-progress"]'),
    );
    activeTab.nativeElement.click();
    fixture.detectChanges();

    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="task-item"]'),
    );
    expect(items.length).toBe(1);
    expect(items[0].nativeElement.textContent).toContain('Active task B');
  });

  it('should filter tasks by search query', () => {
    // 先切到 all
    fixture.debugElement
      .query(By.css('[data-testid="tab-all"]'))
      .nativeElement.click();
    fixture.detectChanges();

    const searchInput = fixture.debugElement.query(
      By.css('[data-testid="task-search"]'),
    );
    searchInput.nativeElement.value = 'Another';
    searchInput.nativeElement.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="task-item"]'),
    );
    expect(items.length).toBe(1);
    expect(items[0].nativeElement.textContent).toContain('Another todo');
  });

  it('should call advanceTask with start when start button clicked', () => {
    // todo filter is default, task-1 has a start button
    const startBtn = fixture.debugElement.query(
      By.css('[data-testid="task-start"]'),
    );
    expect(startBtn).toBeTruthy();

    startBtn.nativeElement.click();
    fixture.detectChanges();

    expect(planService.advanceTask).toHaveBeenCalledWith('task-1', 'start');
  });

  it('should call advanceTask with complete when complete button clicked', () => {
    // 切到 in-progress tab
    fixture.debugElement
      .query(By.css('[data-testid="tab-in-progress"]'))
      .nativeElement.click();
    fixture.detectChanges();

    const completeBtn = fixture.debugElement.query(
      By.css('[data-testid="task-complete"]'),
    );
    expect(completeBtn).toBeTruthy();

    completeBtn.nativeElement.click();
    fixture.detectChanges();

    expect(planService.advanceTask).toHaveBeenCalledWith('task-2', 'complete');
  });

  it('should display correct tab counts', () => {
    const el = fixture.nativeElement as HTMLElement;
    // todo tab should show count 2
    const todoTab = fixture.debugElement.query(
      By.css('[data-testid="tab-todo"]'),
    );
    expect(todoTab.nativeElement.textContent).toContain('2');

    const activeTab = fixture.debugElement.query(
      By.css('[data-testid="tab-in-progress"]'),
    );
    expect(activeTab.nativeElement.textContent).toContain('1');
  });

  it('should show empty state when no tasks match filter', () => {
    // 切到 someday
    fixture.debugElement
      .query(By.css('[data-testid="tab-someday"]'))
      .nativeElement.click();
    fixture.detectChanges();

    // 搜尋不存在的東西
    const searchInput = fixture.debugElement.query(
      By.css('[data-testid="task-search"]'),
    );
    searchInput.nativeElement.value = 'nonexistent';
    searchInput.nativeElement.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="task-item"]'),
    );
    expect(items.length).toBe(0);
  });
});
