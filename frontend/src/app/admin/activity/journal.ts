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
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ScrollText,
  Target,
  PenLine,
  MessageSquare,
  BarChart3,
} from 'lucide-angular';
import { ReflectService } from '../../core/services/reflect.service';
import { NotificationService } from '../../core/services/notification.service';
import type { JournalEntry, JournalKind } from '../../core/models/admin.model';

type JournalFilter = 'all' | JournalKind;

@Component({
  selector: 'app-journal',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './journal.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class JournalComponent implements OnInit {
  private readonly reflectService = inject(ReflectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly entries = signal<JournalEntry[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly activeFilter = signal<JournalFilter>('all');

  protected readonly filteredEntries = computed(() => {
    const filter = this.activeFilter();
    const all = this.entries();
    if (filter === 'all') return all;
    return all.filter((e) => e.kind === filter);
  });

  protected readonly filterTabs: { key: JournalFilter; label: string }[] = [
    { key: 'all', label: 'All' },
    { key: 'plan', label: 'Plan' },
    { key: 'reflection', label: 'Reflection' },
    { key: 'context', label: 'Context' },
    { key: 'metrics', label: 'Metrics' },
  ];

  protected readonly KIND_CLASSES: Record<string, string | undefined> = {
    plan: 'bg-sky-900/40 text-sky-400',
    reflection: 'bg-violet-900/40 text-violet-400',
    context: 'bg-amber-900/40 text-amber-400',
    metrics: 'bg-emerald-900/40 text-emerald-400',
  };

  protected readonly KIND_LABELS: Record<string, string | undefined> = {
    plan: 'Plan',
    reflection: 'Reflection',
    context: 'Context',
    metrics: 'Metrics',
  };

  // Lucide icons
  protected readonly ScrollTextIcon = ScrollText;
  protected readonly TargetIcon = Target;
  protected readonly PenLineIcon = PenLine;
  protected readonly MessageSquareIcon = MessageSquare;
  protected readonly BarChart3Icon = BarChart3;

  ngOnInit(): void {
    this.loadEntries();
  }

  private loadEntries(): void {
    this.isLoading.set(true);
    this.reflectService
      .getJournalEntries()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.entries.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load journal');
        },
      });
  }

  protected setFilter(filter: JournalFilter): void {
    this.activeFilter.set(filter);
  }

  protected getKindIcon(kind: string): typeof ScrollText {
    switch (kind) {
      case 'plan':
        return Target;
      case 'reflection':
        return PenLine;
      case 'context':
        return MessageSquare;
      case 'metrics':
        return BarChart3;
      default:
        return ScrollText;
    }
  }
}
