import {
  Component,
  ChangeDetectionStrategy,
  inject,
  input,
  signal,
  computed,
  type OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LucideAngularModule, BarChart3, Loader2 } from 'lucide-angular';
import { SessionNoteService } from '../../core/services/session-note.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiSessionNote } from '../../core/models';

const DAY_LABELS = ['日', '一', '二', '三', '四', '五', '六'];

const MIN_DATA_POINTS = 3;
const TREND_WINDOW = 14;
const HEATMAP_MIN_POINTS = 2;

interface MetricsData {
  noteDate: string;
  dayOfWeek: number;
  tasksPlanned: number;
  tasksCompleted: number;
  tasksCommitted: number;
  tasksPulled: number;
  completionRate: number;
  committedCompletionRate: number;
}

interface DayTrendBox {
  label: string;
  rate: number | null;
}

interface DayHeatmapEntry {
  label: string;
  avgCapacity: number | null;
  dataPoints: number;
}

@Component({
  selector: 'app-planning',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './planning.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PlanningComponent implements OnInit {
  readonly hideHeader = input(false);

  private readonly sessionNoteService = inject(SessionNoteService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly isLoading = signal(true);
  protected readonly metricsNotes = signal<ApiSessionNote[]>([]);

  protected readonly BarChartIcon = BarChart3;
  protected readonly Loader2Icon = Loader2;

  // ─── Parsed metrics ───
  protected readonly metrics = computed<MetricsData[]>(() => {
    return this.metricsNotes()
      .map((note) => this.parseMetrics(note))
      .filter((m): m is MetricsData => m !== null);
  });

  protected readonly hasEnoughData = computed(
    () => this.metrics().length >= MIN_DATA_POINTS,
  );

  // ─── Block 1: 完成率趨勢（最近 14 天）───
  protected readonly trendBoxes = computed<DayTrendBox[]>(() => {
    const data = this.metrics();
    const boxes: DayTrendBox[] = [];
    const today = new Date();

    for (let i = TREND_WINDOW - 1; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const dateStr = this.toDateString(d);
      const dayLabel = DAY_LABELS[d.getDay()];
      const match = data.find((m) => m.noteDate === dateStr);
      boxes.push({
        label: dayLabel,
        rate: match ? Math.round(match.completionRate * 100) : null,
      });
    }

    return boxes;
  });

  protected readonly trendAvg = computed(() => {
    const boxes = this.trendBoxes().filter((b) => b.rate !== null);
    if (boxes.length === 0) return 0;
    const sum = boxes.reduce((acc, b) => acc + (b.rate ?? 0), 0);
    return Math.round(sum / boxes.length);
  });

  // ─── Block 2: Capacity 分析 ───
  protected readonly weekdayAvg = computed(() => {
    const data = this.metrics().filter(
      (m) => m.dayOfWeek >= 1 && m.dayOfWeek <= 5,
    );
    return this.computeCapacityAvg(data);
  });

  protected readonly weekendAvg = computed(() => {
    const data = this.metrics().filter(
      (m) => m.dayOfWeek === 0 || m.dayOfWeek === 6,
    );
    return this.computeCapacityAvg(data);
  });

  protected readonly committedCompletionAvg = computed(() => {
    const data = this.metrics().filter((m) => m.committedCompletionRate > 0);
    if (data.length === 0) return 0;
    const sum = data.reduce((acc, m) => acc + m.committedCompletionRate, 0);
    return Math.round((sum / data.length) * 100);
  });

  // ─── Block 3: Day-of-Week 熱力圖 ───
  protected readonly heatmapEntries = computed<DayHeatmapEntry[]>(() => {
    const data = this.metrics();
    const grouped = new Map<number, MetricsData[]>();

    for (const m of data) {
      const existing = grouped.get(m.dayOfWeek) ?? [];
      existing.push(m);
      grouped.set(m.dayOfWeek, existing);
    }

    const entries: DayHeatmapEntry[] = [];
    // Mon(1) -> Sun(0)
    const dayOrder = [1, 2, 3, 4, 5, 6, 0];

    for (const dow of dayOrder) {
      const items = grouped.get(dow) ?? [];
      const label = DAY_LABELS[dow];
      if (items.length < HEATMAP_MIN_POINTS) {
        entries.push({ label, avgCapacity: null, dataPoints: items.length });
      } else {
        const avg =
          items.reduce((sum, m) => sum + m.tasksCommitted + m.tasksPulled, 0) /
          items.length;
        entries.push({
          label,
          avgCapacity: Math.round(avg * 10) / 10,
          dataPoints: items.length,
        });
      }
    }

    return entries;
  });

  protected readonly maxCapacity = computed(() => {
    const entries = this.heatmapEntries().filter((e) => e.avgCapacity !== null);
    if (entries.length === 0) return 0;
    return Math.max(...entries.map((e) => e.avgCapacity ?? 0));
  });

  // ─── Block 4: 月度摘要 ───
  protected readonly totalDaysTracked = computed(() => this.metrics().length);

  protected readonly overallAvgCompletionRate = computed(() => {
    const data = this.metrics();
    if (data.length === 0) return 0;
    const sum = data.reduce((acc, m) => acc + m.completionRate, 0);
    return Math.round((sum / data.length) * 100);
  });

  protected readonly bestAndWorstDay = computed(() => {
    const entries = this.heatmapEntries().filter((e) => e.avgCapacity !== null);
    if (entries.length === 0) return { best: '—', worst: '—' };

    let bestEntry = entries[0];
    let worstEntry = entries[0];

    for (const e of entries) {
      if ((e.avgCapacity ?? 0) > (bestEntry.avgCapacity ?? 0)) {
        bestEntry = e;
      }
      if ((e.avgCapacity ?? 0) < (worstEntry.avgCapacity ?? 0)) {
        worstEntry = e;
      }
    }

    return {
      best: `週${bestEntry.label}`,
      worst: `週${worstEntry.label}`,
    };
  });

  protected readonly trend = computed(() => {
    const data = this.metrics();
    if (data.length < TREND_WINDOW) return '→';

    const sorted = [...data].sort((a, b) =>
      a.noteDate.localeCompare(b.noteDate),
    );
    const recent = sorted.slice(-7);
    const previous = sorted.slice(-14, -7);

    if (recent.length === 0 || previous.length === 0) return '→';

    const recentAvg =
      recent.reduce((s, m) => s + m.completionRate, 0) / recent.length;
    const previousAvg =
      previous.reduce((s, m) => s + m.completionRate, 0) / previous.length;

    const diff = recentAvg - previousAvg;
    if (diff > 0.05) return '↑';
    if (diff < -0.05) return '↓';
    return '→';
  });

  // ─── Helpers for template ───

  protected rateColorClass(rate: number | null): string {
    if (rate === null) return 'text-zinc-600';
    if (rate < 50) return 'text-red-400';
    if (rate <= 80) return 'text-amber-400';
    return 'text-emerald-400';
  }

  protected heatmapOpacity(entry: DayHeatmapEntry): string {
    const max = this.maxCapacity();
    if (entry.avgCapacity === null || max === 0) return 'opacity-20';
    const ratio = entry.avgCapacity / max;
    if (ratio >= 0.8) return 'opacity-100';
    if (ratio >= 0.6) return 'opacity-80';
    if (ratio >= 0.4) return 'opacity-60';
    if (ratio >= 0.2) return 'opacity-40';
    return 'opacity-20';
  }

  protected isHighestCapacity(entry: DayHeatmapEntry): boolean {
    return (
      entry.avgCapacity !== null &&
      entry.avgCapacity === this.maxCapacity() &&
      this.maxCapacity() > 0
    );
  }

  protected trendColorClass(): string {
    const t = this.trend();
    if (t === '↑') return 'text-emerald-400';
    if (t === '↓') return 'text-red-400';
    return 'text-zinc-400';
  }

  // ─── Lifecycle ───

  ngOnInit(): void {
    this.loadMetrics();
  }

  private loadMetrics(): void {
    this.sessionNoteService
      .list(undefined, 'metrics', 30)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (notes) => {
          this.metricsNotes.set(notes);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 metrics 資料');
          this.isLoading.set(false);
        },
      });
  }

  private parseMetrics(note: ApiSessionNote): MetricsData | null {
    const meta = note.metadata as Record<string, number> | null;
    if (!meta) return null;

    const noteDate = note.note_date;
    const d = new Date(noteDate + 'T00:00:00');
    const dayOfWeek = d.getDay();

    return {
      noteDate,
      dayOfWeek,
      tasksPlanned: meta['tasks_planned'] ?? 0,
      tasksCompleted: meta['tasks_completed'] ?? 0,
      tasksCommitted: meta['tasks_committed'] ?? 0,
      tasksPulled: meta['tasks_pulled'] ?? 0,
      completionRate: meta['completion_rate'] ?? 0,
      committedCompletionRate: meta['committed_completion_rate'] ?? 0,
    };
  }

  private computeCapacityAvg(data: MetricsData[]): {
    total: number;
    committed: number;
    pulled: number;
  } {
    if (data.length === 0) {
      return { total: 0, committed: 0, pulled: 0 };
    }
    const committed =
      data.reduce((s, m) => s + m.tasksCommitted, 0) / data.length;
    const pulled = data.reduce((s, m) => s + m.tasksPulled, 0) / data.length;
    return {
      total: Math.round((committed + pulled) * 10) / 10,
      committed: Math.round(committed * 10) / 10,
      pulled: Math.round(pulled * 10) / 10,
    };
  }

  private toDateString(d: Date): string {
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }
}
