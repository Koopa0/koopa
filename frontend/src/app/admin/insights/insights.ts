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
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Lightbulb,
  Loader2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Plus,
  Archive,
  ChevronDown,
  ChevronUp,
  X,
} from 'lucide-angular';
import { InsightService } from '../../core/services/insight.service';
import { NotificationService } from '../../core/services/notification.service';
import { MarkdownService } from '../../core/services/markdown.service';
import type { ApiInsight, InsightStatus } from '../../core/models';

type FilterTab = 'unverified' | 'verified' | 'invalidated' | 'all';

interface InsightAction {
  insightId: number;
  type: 'verify' | 'invalidate' | 'evidence';
}

const FILTER_TABS: { value: FilterTab; label: string }[] = [
  { value: 'unverified', label: '待驗證' },
  { value: 'verified', label: '已驗證' },
  { value: 'invalidated', label: '已否決' },
  { value: 'all', label: '全部' },
];

@Component({
  selector: 'app-insights',
  standalone: true,
  imports: [FormsModule, LucideAngularModule],
  templateUrl: './insights.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class InsightsComponent implements OnInit {
  private readonly insightService = inject(InsightService);
  private readonly notificationService = inject(NotificationService);
  private readonly markdownService = inject(MarkdownService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly insights = signal<ApiInsight[]>([]);
  protected readonly isLoading = signal(false);
  protected readonly activeTab = signal<FilterTab>('unverified');
  protected readonly selectedProject = signal<string>('');
  protected readonly expandedInsights = signal<Set<number>>(new Set());
  protected readonly activeAction = signal<InsightAction | null>(null);
  protected readonly actionText = signal('');
  protected readonly fadingOut = signal<Set<number>>(new Set());

  protected readonly filterTabs = FILTER_TABS;

  // ─── Icons ───
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly Loader2Icon = Loader2;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly CheckIcon = CheckCircle2;
  protected readonly XCircleIcon = XCircle;
  protected readonly PlusIcon = Plus;
  protected readonly ArchiveIcon = Archive;
  protected readonly ChevronDownIcon = ChevronDown;
  protected readonly ChevronUpIcon = ChevronUp;
  protected readonly CloseIcon = X;

  // ─── Computed ───

  protected readonly uniqueProjects = computed(() => {
    const projects = new Set<string>();
    for (const insight of this.insights()) {
      if (insight.project) {
        projects.add(insight.project);
      }
    }
    return Array.from(projects).sort();
  });

  protected readonly filteredInsights = computed<ApiInsight[]>(() => {
    const all = this.insights();
    const tab = this.activeTab();
    const project = this.selectedProject();

    let filtered = all;

    // Filter by status tab
    if (tab !== 'all') {
      filtered = filtered.filter((i) => i.status === tab);
    }

    // Filter by project
    if (project) {
      filtered = filtered.filter((i) => i.project === project);
    }

    return filtered;
  });

  protected readonly tabCounts = computed(() => {
    const all = this.insights();
    const project = this.selectedProject();

    const relevant = project ? all.filter((i) => i.project === project) : all;

    return {
      unverified: relevant.filter((i) => i.status === 'unverified').length,
      verified: relevant.filter((i) => i.status === 'verified').length,
      invalidated: relevant.filter((i) => i.status === 'invalidated').length,
      all: relevant.length,
    };
  });

  ngOnInit(): void {
    this.loadInsights();
  }

  protected loadInsights(): void {
    this.isLoading.set(true);
    this.insightService
      .list({ status: 'all' })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.insights.set(response.insights);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Insights');
          this.isLoading.set(false);
        },
      });
  }

  protected setTab(tab: FilterTab): void {
    this.activeTab.set(tab);
    this.cancelAction();
  }

  protected getTabCount(tab: FilterTab): number {
    return this.tabCounts()[tab];
  }

  // ─── Content Display ───

  protected isExpanded(insightId: number): boolean {
    return this.expandedInsights().has(insightId);
  }

  protected toggleExpand(insightId: number): void {
    this.expandedInsights.update((set) => {
      const next = new Set(set);
      if (next.has(insightId)) {
        next.delete(insightId);
      } else {
        next.add(insightId);
      }
      return next;
    });
  }

  protected parseMarkdown(content: string): string {
    return this.markdownService.parse(content);
  }

  protected sourceDateRange(insight: ApiInsight): string {
    if (!insight.source_dates || insight.source_dates.length === 0) return '';
    const sorted = [...insight.source_dates].sort();
    const first = sorted[0].slice(0, 10);
    const last = sorted[sorted.length - 1].slice(0, 10);
    return first === last ? first : `${first} ~ ${last}`;
  }

  protected formatDate(dateStr: string): string {
    return dateStr.slice(0, 10);
  }

  protected isFadingOut(insightId: number): boolean {
    return this.fadingOut().has(insightId);
  }

  // ─── Actions ───

  protected showAction(insightId: number, type: 'verify' | 'invalidate' | 'evidence'): void {
    this.activeAction.set({ insightId, type });
    this.actionText.set('');
  }

  protected isActionActive(insightId: number, type: 'verify' | 'invalidate' | 'evidence'): boolean {
    const action = this.activeAction();
    return action !== null && action.insightId === insightId && action.type === type;
  }

  protected hasActiveAction(insightId: number): boolean {
    const action = this.activeAction();
    return action !== null && action.insightId === insightId;
  }

  protected cancelAction(): void {
    this.activeAction.set(null);
    this.actionText.set('');
  }

  protected submitVerify(insight: ApiInsight): void {
    const conclusion = this.actionText().trim();
    this.cancelAction();

    // Fade out animation
    this.fadingOut.update((set) => new Set(set).add(insight.id));

    // Optimistic update
    this.insights.update((list) =>
      list.map((i) =>
        i.id === insight.id ? { ...i, status: 'verified' as InsightStatus, conclusion } : i,
      ),
    );

    this.insightService
      .update(insight.id, { status: 'verified', conclusion: conclusion || undefined })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('Insight 已驗證');
          this.fadingOut.update((set) => {
            const next = new Set(set);
            next.delete(insight.id);
            return next;
          });
        },
        error: () => {
          // Rollback
          this.insights.update((list) =>
            list.map((i) =>
              i.id === insight.id ? { ...i, status: 'unverified' as InsightStatus, conclusion: '' } : i,
            ),
          );
          this.fadingOut.update((set) => {
            const next = new Set(set);
            next.delete(insight.id);
            return next;
          });
          this.notificationService.error('驗證 Insight 失敗');
        },
      });
  }

  protected submitInvalidate(insight: ApiInsight): void {
    const conclusion = this.actionText().trim();
    this.cancelAction();

    this.fadingOut.update((set) => new Set(set).add(insight.id));

    this.insights.update((list) =>
      list.map((i) =>
        i.id === insight.id ? { ...i, status: 'invalidated' as InsightStatus, conclusion } : i,
      ),
    );

    this.insightService
      .update(insight.id, { status: 'invalidated', conclusion: conclusion || undefined })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('Insight 已否決');
          this.fadingOut.update((set) => {
            const next = new Set(set);
            next.delete(insight.id);
            return next;
          });
        },
        error: () => {
          this.insights.update((list) =>
            list.map((i) =>
              i.id === insight.id ? { ...i, status: 'unverified' as InsightStatus, conclusion: '' } : i,
            ),
          );
          this.fadingOut.update((set) => {
            const next = new Set(set);
            next.delete(insight.id);
            return next;
          });
          this.notificationService.error('否決 Insight 失敗');
        },
      });
  }

  protected submitEvidence(insight: ApiInsight): void {
    const text = this.actionText().trim();
    if (!text) return;

    this.cancelAction();

    // Optimistic update — append evidence
    const previousEvidence = [...insight.evidence];
    this.insights.update((list) =>
      list.map((i) =>
        i.id === insight.id ? { ...i, evidence: [...i.evidence, text] } : i,
      ),
    );

    this.insightService
      .update(insight.id, { append_evidence: text })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('已補充 evidence');
        },
        error: () => {
          // Rollback
          this.insights.update((list) =>
            list.map((i) =>
              i.id === insight.id ? { ...i, evidence: previousEvidence } : i,
            ),
          );
          this.notificationService.error('補充 evidence 失敗');
        },
      });
  }

  protected archiveInsight(insight: ApiInsight): void {
    // Optimistic remove
    const previousInsights = this.insights();
    this.insights.update((list) => list.filter((i) => i.id !== insight.id));

    this.insightService
      .update(insight.id, { status: 'archived' })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('Insight 已封存');
        },
        error: () => {
          this.insights.set(previousInsights);
          this.notificationService.error('封存 Insight 失敗');
        },
      });
  }
}
