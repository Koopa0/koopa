import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import {
  LucideAngularModule,
  Inbox,
  Plus,
  FileText,
  Lightbulb,
  BookOpen,
  Trash2,
  ListTodo,
  ChevronRight,
  Clock,
  X,
} from 'lucide-angular';
import { InboxService } from '../../core/services/inbox.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  InboxItem,
  InboxStats,
  ClarifyDecision,
} from '../../core/models/admin.model';

type ClarifyTarget = 'task' | 'journal' | 'insight' | 'discard';

@Component({
  selector: 'app-inbox',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './inbox.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class InboxComponent implements OnInit {
  private readonly inboxService = inject(InboxService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly items = signal<InboxItem[]>([]);
  protected readonly stats = signal<InboxStats | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly captureText = signal('');
  protected readonly activeClarifyId = signal<string | null>(null);
  protected readonly selectedClarifyType = signal<ClarifyTarget | null>(null);

  protected readonly activeItem = computed(() => {
    const id = this.activeClarifyId();
    if (!id) return null;
    return this.items().find((i) => i.id === id) ?? null;
  });

  // Icons
  protected readonly InboxIcon = Inbox;
  protected readonly PlusIcon = Plus;
  protected readonly FileTextIcon = FileText;
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly BookOpenIcon = BookOpen;
  protected readonly Trash2Icon = Trash2;
  protected readonly ListTodoIcon = ListTodo;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly ClockIcon = Clock;
  protected readonly XIcon = X;

  ngOnInit(): void {
    this.loadInbox();
  }

  private loadInbox(): void {
    this.isLoading.set(true);
    this.inboxService
      .getInbox()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.items.set(res.items);
          this.stats.set(res.stats);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('無法載入 inbox');
        },
      });
  }

  protected onCaptureInput(event: Event): void {
    this.captureText.set((event.target as HTMLInputElement).value);
  }

  protected capture(): void {
    const text = this.captureText().trim();
    if (!text) return;

    this.inboxService
      .capture(text)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (item) => {
          this.items.update((list) => [item, ...list]);
          this.captureText.set('');
          this.stats.update((s) => (s ? { ...s, total: s.total + 1 } : s));
        },
        error: () => this.notificationService.error('捕獲失敗'),
      });
  }

  protected onCaptureKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.capture();
    }
  }

  protected openClarify(itemId: string): void {
    this.activeClarifyId.set(itemId);
    this.selectedClarifyType.set(null);
  }

  protected closeClarify(): void {
    this.activeClarifyId.set(null);
    this.selectedClarifyType.set(null);
  }

  protected selectClarifyType(type: ClarifyTarget): void {
    this.selectedClarifyType.set(type);
  }

  protected confirmClarify(): void {
    const id = this.activeClarifyId();
    const type = this.selectedClarifyType();
    if (!id || !type) return;

    let decision: ClarifyDecision;
    switch (type) {
      case 'task':
        decision = { type: 'task' };
        break;
      case 'journal':
        decision = { type: 'journal', kind: 'reflection', body: '' };
        break;
      case 'insight':
        decision = { type: 'insight', hypothesis: '', initial_evidence: '' };
        break;
      case 'discard':
        decision = { type: 'discard' };
        break;
    }

    this.inboxService
      .clarify(id, decision)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.items.update((list) => list.filter((i) => i.id !== id));
          this.stats.update((s) =>
            s ? { ...s, total: Math.max(0, s.total - 1) } : s,
          );
          this.closeClarify();
          const labels: Record<ClarifyTarget, string> = {
            task: '已轉為任務',
            journal: '已寫入日誌',
            insight: '已建立洞察',
            discard: '已刪除',
          };
          this.notificationService.success(labels[type]);
        },
        error: () => this.notificationService.error('澄清失敗'),
      });
  }

  protected getSourceLabel(source: string): string {
    const labels: Record<string, string> = {
      manual: '手動',
      mcp: 'MCP',
      rss: 'RSS',
    };
    return labels[source] ?? source;
  }

  protected getSourceColor(source: string): string {
    const colors: Record<string, string> = {
      manual: 'bg-zinc-800 text-zinc-400',
      mcp: 'bg-violet-900/40 text-violet-400',
      rss: 'bg-amber-900/40 text-amber-400',
    };
    return colors[source] ?? 'bg-zinc-800 text-zinc-400';
  }

  protected formatAge(hours: number): string {
    if (hours < 1) return '剛才';
    if (hours < 24) return `${Math.round(hours)}h ago`;
    const days = Math.round(hours / 24);
    return `${days}d ago`;
  }
}
