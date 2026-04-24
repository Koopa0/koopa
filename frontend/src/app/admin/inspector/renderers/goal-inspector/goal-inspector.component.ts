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
import type { GoalDetail } from '../../../../core/models/admin.model';

type GoalTab = 'overview' | 'activity';

@Component({
  selector: 'app-goal-inspector',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './goal-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GoalInspectorComponent {
  readonly id = input.required<string>();

  private readonly planService = inject(PlanService);

  protected readonly activeTab = signal<GoalTab>('overview');

  protected readonly resource = rxResource<GoalDetail, string>({
    params: () => this.id(),
    stream: ({ params }) => this.planService.getGoalDetail(params),
  });

  protected readonly goal = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly milestoneProgress = computed(() => {
    const ms = this.goal()?.milestones ?? [];
    if (ms.length === 0) return null;
    const done = ms.filter((m) => m.completed).length;
    return {
      done,
      total: ms.length,
      percent: Math.round((done / ms.length) * 100),
    };
  });

  protected setTab(tab: GoalTab): void {
    this.activeTab.set(tab);
  }
}
