import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';
import { PlanService } from '../../core/services/plan.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  GoalSummary,
  ProjectSummary,
} from '../../core/models/admin.model';

export type AtlasItemType = 'goal' | 'project';

export interface AtlasItem {
  type: AtlasItemType;
  id: string;
  title: string;
  area: string;
  status: string;
  /** Pre-computed lowercase haystack for the search filter */
  searchHaystack: string;
}

/**
 * ATLAS mode — faceted cross-entity search.
 *
 * Phase 1 baseline scope: goals + projects merged into a single sortable,
 * filterable list. Type facet (Goal / Project) on the left rail, search
 * input above the result list, every row clickable into the Inspector via
 * the same ?inspect=type:id pattern used everywhere else. Concepts and
 * directives land later when the corresponding inspector renderers ship.
 */
@Component({
  selector: 'app-atlas-page',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './atlas-page.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AtlasPageComponent implements OnInit {
  private readonly planService = inject(PlanService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly items = signal<AtlasItem[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly query = signal('');
  protected readonly enabledTypes = signal<Set<AtlasItemType>>(
    new Set(['goal', 'project']),
  );

  protected readonly filteredItems = computed<AtlasItem[]>(() => {
    const q = this.query().trim().toLowerCase();
    const types = this.enabledTypes();
    return this.items().filter((item) => {
      if (!types.has(item.type)) return false;
      if (q && !item.searchHaystack.includes(q)) return false;
      return true;
    });
  });

  protected readonly counts = computed(() => {
    const all = this.filteredItems();
    return {
      total: all.length,
      goal: all.filter((i) => i.type === 'goal').length,
      project: all.filter((i) => i.type === 'project').length,
    };
  });

  protected readonly STATUS_COLOR: Record<string, string | undefined> = {
    'in-progress': 'text-sky-400',
    'on-hold': 'text-amber-400',
    'not-started': 'text-zinc-500',
    planned: 'text-zinc-400',
    done: 'text-emerald-400',
    completed: 'text-emerald-400',
    maintained: 'text-blue-400',
    abandoned: 'text-zinc-600',
    archived: 'text-zinc-600',
  };

  ngOnInit(): void {
    this.loadAll();
  }

  protected onSearchInput(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
  }

  protected toggleType(type: AtlasItemType): void {
    this.enabledTypes.update((set) => {
      const next = new Set(set);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  }

  protected isTypeEnabled(type: AtlasItemType): boolean {
    return this.enabledTypes().has(type);
  }

  protected statusColor(status: string): string {
    return this.STATUS_COLOR[status] ?? 'text-zinc-400';
  }

  protected typeIcon(type: AtlasItemType): string {
    return type === 'goal' ? '◆' : '▣';
  }

  private loadAll(): void {
    this.isLoading.set(true);
    forkJoin({
      goals: this.planService.getGoalsOverview(),
      projects: this.planService.getProjectsOverview(),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ goals, projects }) => {
          const goalItems = goals.by_area.flatMap((area) =>
            area.goals.map((g) => this.toGoalItem(g, area.area_name)),
          );
          const projectItems = projects.projects.map((p) =>
            this.toProjectItem(p),
          );
          this.items.set([...goalItems, ...projectItems]);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load atlas');
        },
      });
  }

  private toGoalItem(g: GoalSummary, areaName: string): AtlasItem {
    return {
      type: 'goal',
      id: g.id,
      title: g.title,
      area: areaName,
      status: g.status,
      searchHaystack:
        `${g.title} ${areaName} ${g.quarter} ${g.status}`.toLowerCase(),
    };
  }

  private toProjectItem(p: ProjectSummary): AtlasItem {
    return {
      type: 'project',
      id: p.id,
      title: p.title,
      area: p.area,
      status: p.status,
      searchHaystack: `${p.title} ${p.area} ${p.status}`.toLowerCase(),
    };
  }
}
