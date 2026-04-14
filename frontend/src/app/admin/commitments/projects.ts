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
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  FolderOpen,
  Target,
  ChevronRight,
} from 'lucide-angular';
import { PlanService } from '../../core/services/plan.service';
import { NotificationService } from '../../core/services/notification.service';
import { InspectorService } from '../inspector/inspector.service';
import type { ProjectSummary } from '../../core/models/admin.model';

const STATUS_FILTERS = [
  'active',
  'planned',
  'in-progress',
  'on-hold',
  'completed',
  'maintained',
  'archived',
] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

@Component({
  selector: 'app-projects',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './projects.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectsComponent implements OnInit {
  private readonly planService = inject(PlanService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly inspector = inject(InspectorService);

  protected readonly projects = signal<ProjectSummary[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly selectedFilter = signal<StatusFilter>('active');

  protected readonly statusFilters = STATUS_FILTERS;

  protected readonly projectsByGoal = computed(() => {
    const items = this.projects();
    const grouped = new Map<
      string,
      { goal_title: string | null; projects: ProjectSummary[] }
    >();

    for (const p of items) {
      const key = p.goal_breadcrumb?.goal_id ?? '__unlinked__';
      const title = p.goal_breadcrumb?.goal_title ?? null;
      const existing = grouped.get(key);
      if (existing) {
        existing.projects.push(p);
      } else {
        grouped.set(key, { goal_title: title, projects: [p] });
      }
    }

    return Array.from(grouped.values());
  });

  // Icons
  protected readonly FolderOpenIcon = FolderOpen;
  protected readonly TargetIcon = Target;
  protected readonly ChevronRightIcon = ChevronRight;

  protected readonly STATUS_COLORS: Record<string, string | undefined> = {
    planned: 'text-zinc-400 bg-zinc-800/50 border-zinc-700/50',
    'in-progress': 'text-sky-400 bg-sky-950/30 border-sky-800/30',
    'on-hold': 'text-amber-400 bg-amber-950/30 border-amber-800/30',
    completed: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
    maintained: 'text-blue-400 bg-blue-950/30 border-blue-800/30',
    archived: 'text-zinc-500 bg-zinc-800/30 border-zinc-700/30',
  };

  ngOnInit(): void {
    this.loadProjects();
  }

  protected selectFilter(filter: StatusFilter): void {
    this.selectedFilter.set(filter);
    this.loadProjects();
  }

  private loadProjects(): void {
    this.isLoading.set(true);
    this.planService
      .getProjectsOverview(this.selectedFilter())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.projects.set(data.projects);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load projects');
        },
      });
  }

  protected getStatusColor(status: string): string {
    return (
      this.STATUS_COLORS[status] ??
      'text-zinc-400 bg-zinc-800/50 border-zinc-700'
    );
  }

  protected getStalenessColor(days: number): string {
    if (days > 30) return 'text-red-400';
    if (days > 14) return 'text-amber-400';
    if (days > 7) return 'text-zinc-400';
    return 'text-zinc-600';
  }

  protected getProgressPercent(p: ProjectSummary): number {
    if (p.task_progress.total === 0) return 0;
    return Math.round((p.task_progress.done / p.task_progress.total) * 100);
  }

  /**
   * Plain click → open Inspector. Modifier click falls through to the
   * legacy detail route via routerLink. See goals.ts for rationale.
   */
  protected onRowClick(event: MouseEvent, project: ProjectSummary): void {
    if (
      event.ctrlKey ||
      event.metaKey ||
      event.shiftKey ||
      event.button !== 0
    ) {
      return;
    }
    event.preventDefault();
    this.inspector.open({ type: 'project', id: project.id });
  }
}
