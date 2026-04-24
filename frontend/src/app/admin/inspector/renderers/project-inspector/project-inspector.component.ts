import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { PlanService } from '../../../../core/services/plan.service';
import type { ProjectDetail } from '../../../../core/models/admin.model';

type ProjectTab = 'overview' | 'activity';

@Component({
  selector: 'app-project-inspector',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './project-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectInspectorComponent {
  readonly id = input.required<string>();

  private readonly planService = inject(PlanService);

  protected readonly activeTab = signal<ProjectTab>('overview');

  protected readonly resource = rxResource<ProjectDetail, string>({
    params: () => this.id(),
    stream: ({ params }) => this.planService.getProjectDetail(params),
  });

  protected readonly project = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly taskCounts = computed(() => {
    const tbs = this.project()?.todos_by_state;
    if (!tbs) return null;
    return {
      inProgress: tbs.in_progress.length,
      todo: tbs.todo.length,
      done: tbs.done.length,
      someday: tbs.someday.length,
    };
  });

  protected setTab(tab: ProjectTab): void {
    this.activeTab.set(tab);
  }
}
