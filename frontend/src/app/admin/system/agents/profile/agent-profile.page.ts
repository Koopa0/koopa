import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { map } from 'rxjs';
import { AgentService } from '../../../../core/services/agent.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { AgentDetail } from '../../../../core/models/workbench.model';

/**
 * Agent Profile. Read-only registry view showing the hero (name /
 * display_name / platform / status / schedule) and capability badges
 * (submit_tasks / receive_tasks / publish_artifacts).
 */
@Component({
  selector: 'app-agent-profile-page',
  imports: [DatePipe],
  templateUrl: './agent-profile.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class AgentProfilePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly agentService = inject(AgentService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly nameFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('name') ?? '')),
    { initialValue: '' },
  );

  protected readonly agentResource = rxResource<AgentDetail, string>({
    params: () => this.nameFromRoute(),
    stream: ({ params }) => this.agentService.get(params),
  });

  // Guard with hasValue(): rxResource.value() throws in the loading/error
  // state, and the topbar effect below reads agent() unconditionally.
  protected readonly agent = computed(() =>
    this.agentResource.hasValue() ? this.agentResource.value() : undefined,
  );

  protected readonly isLoading = computed(
    () => this.agentResource.status() === 'loading' && !this.agent(),
  );
  protected readonly hasError = computed(
    () => this.agentResource.status() === 'error',
  );

  constructor() {
    this.topbar.set({
      title: 'Agent',
      crumbs: ['System', 'Agents'],
    });

    effect(() => {
      const a = this.agent();
      if (!a) return;
      this.topbar.set({
        title: `Agent · ${a.display_name}`,
        crumbs: ['System', 'Agents', a.name],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected back(): void {
    this.router.navigate(['/admin/system/agents']);
  }
}
