import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';

import { TodayPageComponent } from './today-page.component';
import { TodayService, type TodayVm } from './today.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

// Track 1B-correction — pins the Today plan region at the PRODUCT surface
// (component render), using a view-model whose plan items carry the
// backend-mapped fields {id, title, status}. This proves:
//   - the plan row renders `item.title` (not the fictional `todo_title`);
//   - glyphs derive from `item.status` (done → ✓), not nonexistent fields;
//   - the active-items list filters on `status==='planned'`, not `todo_state`.
// A VM with fictional items (e.g. {todo_title, todo_state}) would render blank
// rows and all-'·' glyphs, failing these assertions.

function vmWithPlan(): TodayVm {
  return {
    date: '2026-05-21',
    awaitingJudgment: [],
    plan: {
      date: '2026-05-21',
      items: [
        { id: 'p1', title: 'Fix auth middleware', status: 'planned' },
        { id: 'p2', title: 'Ship release notes', status: 'done' },
      ],
      total: 2,
      done: 1,
      overdue: 0,
    },
    warnings: [],
  };
}

describe('TodayPageComponent — plan region render', () => {
  let fixture: ComponentFixture<TodayPageComponent>;

  afterEach(() => TestBed.resetTestingModule());

  async function render(vm: TodayVm): Promise<void> {
    TestBed.configureTestingModule({
      imports: [TodayPageComponent],
      providers: [
        provideRouter([]),
        { provide: TodayService, useValue: { today: () => of(vm) } },
        { provide: AdminTopbarService, useValue: { set: () => undefined, reset: () => undefined } },
      ],
    });
    fixture = TestBed.createComponent(TodayPageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('renders the active plan item title from the backend-mapped `title` field', async () => {
    await render(vmWithPlan());

    const active = fixture.nativeElement.querySelector(
      '[data-testid="today-plan-active"]',
    ) as HTMLElement;
    expect(active).toBeTruthy();
    // Planned item renders; the done item is not "active".
    expect(active.textContent).toContain('Fix auth middleware');
    expect(active.textContent).not.toContain('Ship release notes');
  });

  it('derives plan glyphs from `status` (done → ✓)', async () => {
    await render(vmWithPlan());

    const glyphs = fixture.nativeElement.querySelector(
      '[data-testid="today-plan-glyphs"]',
    ) as HTMLElement;
    expect(glyphs).toBeTruthy();
    // One done item → a ✓ glyph present; planned item → ·.
    expect(glyphs.textContent).toContain('✓');
    expect(glyphs.textContent).toContain('·');
  });
});
