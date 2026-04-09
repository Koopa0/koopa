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
  JournalKind,
} from '../../core/models/admin.model';

type ClarifyTarget = 'task' | 'journal' | 'insight' | 'discard';

interface AreaOption {
  readonly slug: string;
  readonly name: string;
}

const AREAS: readonly AreaOption[] = [
  { slug: 'backend', name: 'Backend' },
  { slug: 'learning', name: 'Learning' },
  { slug: 'studio', name: 'Studio' },
  { slug: 'frontend', name: 'Frontend' },
  { slug: 'career', name: 'Career' },
  { slug: 'ops', name: 'Ops' },
] as const;

type PriorityLevel = 'high' | 'medium' | 'low';
type EnergyLevel = 'high' | 'medium' | 'low';

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

  // Insight form signals
  protected readonly insightHypothesis = signal('');
  protected readonly insightInvalidation = signal('');
  protected readonly insightEvidence = signal('');

  // Journal form signals
  protected readonly journalBody = signal('');
  protected readonly journalKind = signal<JournalKind>('reflection');

  // Task form signals
  protected readonly taskAreaId = signal<string | null>(null);
  protected readonly taskPriority = signal<PriorityLevel | null>(null);
  protected readonly taskEnergy = signal<EnergyLevel | null>(null);

  // Constants for template
  protected readonly areas = AREAS;
  protected readonly journalKinds: readonly JournalKind[] = [
    'plan',
    'reflection',
    'context',
    'metrics',
  ];
  protected readonly priorityLevels: readonly PriorityLevel[] = [
    'high',
    'medium',
    'low',
  ];
  protected readonly energyLevels: readonly EnergyLevel[] = [
    'high',
    'medium',
    'low',
  ];

  protected readonly isConfirmDisabled = computed(() => {
    const type = this.selectedClarifyType();
    if (!type) return true;
    if (type === 'insight') {
      return (
        !this.insightHypothesis().trim() || !this.insightInvalidation().trim()
      );
    }
    if (type === 'journal') {
      return !this.journalBody().trim();
    }
    return false;
  });

  protected readonly activeItem = computed(() => {
    const id = this.activeClarifyId();
    if (!id) return null;
    return this.items().find((i) => i.id === id) ?? null;
  });

  // Typed event handlers for textarea inputs
  protected onInsightHypothesisInput(event: Event): void {
    this.insightHypothesis.set((event.target as HTMLTextAreaElement).value);
  }

  protected onInsightInvalidationInput(event: Event): void {
    this.insightInvalidation.set((event.target as HTMLTextAreaElement).value);
  }

  protected onInsightEvidenceInput(event: Event): void {
    this.insightEvidence.set((event.target as HTMLTextAreaElement).value);
  }

  protected onJournalBodyInput(event: Event): void {
    this.journalBody.set((event.target as HTMLTextAreaElement).value);
  }

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
          this.notificationService.error('Failed to load inbox');
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
        error: () => this.notificationService.error('Capture failed'),
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
    this.resetFormSignals();
  }

  private resetFormSignals(): void {
    this.insightHypothesis.set('');
    this.insightInvalidation.set('');
    this.insightEvidence.set('');
    this.journalBody.set('');
    this.journalKind.set('reflection');
    this.taskAreaId.set(null);
    this.taskPriority.set(null);
    this.taskEnergy.set(null);
  }

  protected selectClarifyType(type: ClarifyTarget): void {
    this.resetFormSignals();
    this.selectedClarifyType.set(type);
  }

  protected confirmClarify(): void {
    const id = this.activeClarifyId();
    const type = this.selectedClarifyType();
    if (!id || !type) return;

    let decision: ClarifyDecision;
    switch (type) {
      case 'task': {
        const taskDecision: ClarifyDecision = { type: 'task' };
        const areaId = this.taskAreaId();
        const priority = this.taskPriority();
        const energy = this.taskEnergy();
        if (areaId) taskDecision.area_id = areaId;
        if (priority) taskDecision.priority = priority;
        if (energy) taskDecision.energy = energy;
        decision = taskDecision;
        break;
      }
      case 'journal':
        decision = {
          type: 'journal',
          kind: this.journalKind(),
          body: this.journalBody().trim(),
        };
        break;
      case 'insight':
        decision = {
          type: 'insight',
          hypothesis: this.insightHypothesis().trim(),
          invalidation_condition: this.insightInvalidation().trim(),
          initial_evidence: this.insightEvidence().trim() || undefined,
        };
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
            task: 'Converted to task',
            journal: 'Written to journal',
            insight: 'Insight created',
            discard: 'Deleted',
          };
          this.notificationService.success(labels[type]);
        },
        error: () => this.notificationService.error('Clarification failed'),
      });
  }

  protected getSourceLabel(source: string): string {
    const labels: Record<string, string> = {
      manual: 'Manual',
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
    if (hours < 1) return 'Just now';
    if (hours < 24) return `${Math.round(hours)}h ago`;
    const days = Math.round(hours / 24);
    return `${days}d ago`;
  }
}
