import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map } from 'rxjs';
import {
  AgentService,
  type AgentNoteRow,
} from '../../../../core/services/agent.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  AgentDetail,
  AgentTasksResponse,
} from '../../../../core/models/workbench.model';

type ProfileTab = 'workload' | 'notes';

/**
 * Agent Profile. Shows hero (name / platform / capabilities), current
 * workload (assignee + creator task lists + recent artifacts), and a
 * Context-notes tab backed by `query_agent_notes`. The notes tab
 * degrades gracefully with an info banner when the endpoint 404s.
 */
@Component({
  selector: 'app-agent-profile-page',
  standalone: true,
  imports: [DatePipe, RouterLink],
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

  protected readonly tasksResource = rxResource<AgentTasksResponse, string>({
    params: () => this.nameFromRoute(),
    stream: ({ params }) => this.agentService.tasks(params),
  });

  protected readonly notesResource = rxResource<AgentNoteRow[], string>({
    params: () => this.nameFromRoute(),
    stream: ({ params }) => this.agentService.notes(params),
  });

  protected readonly agent = computed(() => this.agentResource.value());
  protected readonly tasks = computed(() => this.tasksResource.value());
  protected readonly notes = computed(() => this.notesResource.value() ?? []);

  protected readonly isLoading = computed(
    () => this.agentResource.status() === 'loading' && !this.agent(),
  );
  protected readonly hasError = computed(
    () => this.agentResource.status() === 'error',
  );

  /** True when the notes endpoint returns 404/405/501 (not yet live). */
  protected readonly notesUnavailable = computed(() => {
    if (this.notesResource.status() !== 'error') return false;
    const err = this.notesResource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });
  protected readonly notesTransientError = computed(() => {
    if (this.notesResource.status() !== 'error') return false;
    return !this.notesUnavailable();
  });

  protected readonly activeTab = signal<ProfileTab>('workload');

  constructor() {
    this.topbar.set({
      title: 'Agent',
      crumbs: ['Coordination', 'Agents'],
    });

    effect(() => {
      const a = this.agent();
      if (!a) return;
      this.topbar.set({
        title: `Agent · ${a.display_name}`,
        crumbs: ['Coordination', 'Agents', a.name],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setTab(tab: ProfileTab): void {
    this.activeTab.set(tab);
  }

  protected back(): void {
    this.router.navigate(['/admin/coordination/agents']);
  }

  protected noteKindClass(kind: AgentNoteRow['kind']): string {
    switch (kind) {
      case 'plan':
        return 'text-sky-300';
      case 'context':
        return 'text-zinc-300';
      case 'reflection':
        return 'text-amber-300';
    }
  }
}
