import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { By } from '@angular/platform-browser';
import { of } from 'rxjs';
import { InboxComponent } from './inbox';
import { InboxService } from '../../core/services/inbox.service';
import type { InboxResponse } from '../../core/models/admin.model';

const MOCK_INBOX: InboxResponse = {
  items: [
    {
      id: 'inbox-001',
      text: '研究 pgvector indexing',
      source: 'mcp',
      captured_at: '2026-04-08T09:15:00+08:00',
      age_hours: 2,
    },
    {
      id: 'inbox-002',
      text: 'Review Angular defer blocks',
      source: 'manual',
      captured_at: '2026-04-08T08:00:00+08:00',
      age_hours: 3,
    },
  ],
  stats: {
    total: 2,
    oldest_age_days: 0,
    by_source: { mcp: 1, manual: 1 },
  },
};

describe('InboxComponent', () => {
  let component: InboxComponent;
  let fixture: ComponentFixture<InboxComponent>;
  let inboxService: {
    getInbox: ReturnType<typeof vi.fn>;
    capture: ReturnType<typeof vi.fn>;
    clarify: ReturnType<typeof vi.fn>;
  };

  beforeEach(async () => {
    inboxService = {
      getInbox: vi.fn().mockReturnValue(of(MOCK_INBOX)),
      capture: vi.fn().mockReturnValue(
        of({
          id: 'inbox-new',
          text: 'New idea',
          source: 'manual' as const,
          captured_at: new Date().toISOString(),
          age_hours: 0,
        }),
      ),
      clarify: vi
        .fn()
        .mockReturnValue(
          of({
            result: 'clarified' as const,
            entity_type: 'task',
            entity_id: 'task-123',
          }),
        ),
    };

    await TestBed.configureTestingModule({
      imports: [InboxComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        { provide: InboxService, useValue: inboxService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(InboxComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should render inbox items', () => {
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="inbox-item"]'),
    );
    expect(items.length).toBe(2);
    expect(items[0].nativeElement.textContent).toContain(
      '研究 pgvector indexing',
    );
  });

  it('should capture new item when text submitted', () => {
    const input = fixture.debugElement.query(
      By.css('[data-testid="capture-input"]'),
    );
    const btn = fixture.debugElement.query(
      By.css('[data-testid="capture-btn"]'),
    );

    // 模擬輸入
    input.nativeElement.value = 'New idea';
    input.nativeElement.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    btn.nativeElement.click();
    fixture.detectChanges();

    expect(inboxService.capture).toHaveBeenCalledWith('New idea');

    // 新 item 應出現在列表最前
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="inbox-item"]'),
    );
    expect(items.length).toBe(3);
  });

  it('should not capture when text is empty', () => {
    const btn = fixture.debugElement.query(
      By.css('[data-testid="capture-btn"]'),
    );
    btn.nativeElement.click();
    fixture.detectChanges();

    expect(inboxService.capture).not.toHaveBeenCalled();
  });

  it('should open clarify panel when item clicked', () => {
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="inbox-item"]'),
    );
    // 點擊第一個 item 的 button
    const itemBtn = items[0].query(By.css('button'));
    itemBtn.nativeElement.click();
    fixture.detectChanges();

    const panel = fixture.debugElement.query(
      By.css('[data-testid="clarify-panel"]'),
    );
    expect(panel).toBeTruthy();
  });

  it('should show 4 clarify type options', () => {
    // 展開 clarify panel
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="inbox-item"]'),
    );
    items[0].query(By.css('button')).nativeElement.click();
    fixture.detectChanges();

    const taskBtn = fixture.debugElement.query(
      By.css('[data-testid="clarify-task"]'),
    );
    const journalBtn = fixture.debugElement.query(
      By.css('[data-testid="clarify-journal"]'),
    );
    const insightBtn = fixture.debugElement.query(
      By.css('[data-testid="clarify-insight"]'),
    );
    const discardBtn = fixture.debugElement.query(
      By.css('[data-testid="clarify-discard"]'),
    );

    expect(taskBtn).toBeTruthy();
    expect(journalBtn).toBeTruthy();
    expect(insightBtn).toBeTruthy();
    expect(discardBtn).toBeTruthy();
  });

  it('should remove item from list after clarify as task', () => {
    // 展開 clarify
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="inbox-item"]'),
    );
    items[0].query(By.css('button')).nativeElement.click();
    fixture.detectChanges();

    // 選擇 task
    fixture.debugElement
      .query(By.css('[data-testid="clarify-task"]'))
      .nativeElement.click();
    fixture.detectChanges();

    // 確認
    fixture.debugElement
      .query(By.css('[data-testid="clarify-confirm"]'))
      .nativeElement.click();
    fixture.detectChanges();

    expect(inboxService.clarify).toHaveBeenCalledWith('inbox-001', {
      type: 'task',
    });

    const remaining = fixture.debugElement.queryAll(
      By.css('[data-testid="inbox-item"]'),
    );
    expect(remaining.length).toBe(1);
  });

  it('should close clarify panel when cancelled', () => {
    // 展開
    const items = fixture.debugElement.queryAll(
      By.css('[data-testid="inbox-item"]'),
    );
    items[0].query(By.css('button')).nativeElement.click();
    fixture.detectChanges();

    // 選擇 type（需要選擇才會出現 cancel 按鈕）
    fixture.debugElement
      .query(By.css('[data-testid="clarify-task"]'))
      .nativeElement.click();
    fixture.detectChanges();

    // 取消
    fixture.debugElement
      .query(By.css('[data-testid="clarify-cancel"]'))
      .nativeElement.click();
    fixture.detectChanges();

    const panel = fixture.debugElement.query(
      By.css('[data-testid="clarify-panel"]'),
    );
    expect(panel).toBeFalsy();
    expect(inboxService.clarify).not.toHaveBeenCalled();
  });

  describe('when inbox is empty', () => {
    beforeEach(() => {
      inboxService.getInbox.mockReturnValue(
        of({
          items: [],
          stats: { total: 0, oldest_age_days: 0, by_source: {} },
        }),
      );
      fixture = TestBed.createComponent(InboxComponent);
      fixture.detectChanges();
    });

    it('should show empty state', () => {
      const empty = fixture.debugElement.query(
        By.css('[data-testid="inbox-empty"]'),
      );
      expect(empty).toBeTruthy();
      expect(empty.nativeElement.textContent).toContain('Inbox 清空了');
    });
  });
});
