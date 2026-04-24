import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { map } from 'rxjs';
import { PlanService } from '../../../../core/services/plan.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  ProjectDetail,
  TaskSummary,
} from '../../../../core/models/admin.model';

interface TodoColumn {
  key: keyof ProjectDetail['todos_by_state'];
  label: string;
}

const TODO_COLUMNS: readonly TodoColumn[] = [
  { key: 'in_progress', label: 'In progress' },
  { key: 'todo', label: 'Todo' },
  { key: 'done', label: 'Done' },
  { key: 'someday', label: 'Someday' },
];

/**
 * Project Profile Hero + Overview +
 * Problem/Solution/Architecture facets + Todos grouped by state +
 * Related content + Recent activity. Reuses the ✓ existing
 * `GET /api/admin/commitment/projects/:id` endpoint.
 */
@Component({
  selector: 'app-project-profile-page',
  standalone: true,
  imports: [DatePipe, RouterLink],
  templateUrl: './project-profile.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ProjectProfilePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly planService = inject(PlanService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly todoColumns = TODO_COLUMNS;

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<ProjectDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.planService.getProjectDetail(params),
  });

  protected readonly project = computed(() => this.resource.value());
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.project(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly todoTotals = computed(() => {
    const p = this.project();
    if (!p) return { total: 0, done: 0 };
    const s = p.todos_by_state;
    const total =
      s.in_progress.length + s.todo.length + s.done.length + s.someday.length;
    return { total, done: s.done.length };
  });

  protected readonly todoPercent = computed(() => {
    const { total, done } = this.todoTotals();
    if (total === 0) return 0;
    return Math.round((done / total) * 100);
  });

  constructor() {
    this.topbar.set({
      title: 'Project',
      crumbs: ['Commitment', 'Goals & projects'],
    });

    effect(() => {
      const p = this.project();
      if (!p) return;
      this.topbar.set({
        title: `Project · ${truncate(p.title, 40)}`,
        crumbs: p.goal_breadcrumb
          ? ['Commitment', p.goal_breadcrumb.goal_title, p.title]
          : ['Commitment', 'Projects', p.slug],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected back(): void {
    this.router.navigate(['/admin/commitment/goals']);
  }

  protected openGoal(goalId: string): void {
    this.router.navigate(['/admin/commitment/goals', goalId]);
  }

  protected todosForColumn(col: TodoColumn): TaskSummary[] {
    const p = this.project();
    return p ? p.todos_by_state[col.key] : [];
  }
}

function truncate(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}
