import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { LucideAngularModule, Copy as CopyIcon } from 'lucide-angular';
import { AgentService } from '../../../../core/services/agent.service';
import type { Agent } from '../../../../core/models/workbench.model';

/**
 * Agent Inspector renderer — identity card.
 *
 * Renders the read-only registry projection (six fields). The agent has
 * even less depth than a Todo: a single overview with display name,
 * platform, description, schedule, and status. Schedule shows its purpose
 * by default with the raw cron in a <details> progressive disclosure.
 * The `system` agent gets an amber warning — it is the hidden fallback
 * identity for database-level writes. There are no capabilities, tasks, or
 * action buttons; agents are hardcoded registry entries, not
 * workbench-mutable.
 *
 * Backend: GET /api/admin/system/agents/{name}.
 */
@Component({
  selector: 'app-agent-inspector',
  imports: [ClipboardModule, LucideAngularModule],
  templateUrl: './agent-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AgentInspectorComponent {
  readonly id = input.required<string>();

  private readonly agentService = inject(AgentService);

  protected readonly justCopied = signal(false);
  protected readonly CopyIcon = CopyIcon;

  protected readonly resource = rxResource<Agent, string>({
    params: () => this.id(),
    stream: ({ params }) => this.agentService.get(params),
  });

  protected readonly agent = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  /** Schedule purpose, shown as the default human-facing schedule line. */
  protected readonly scheduleText = computed(
    () => this.agent()?.schedule?.purpose ?? null,
  );

  /** True when agent is the hidden `system` fallback identity — surface warning. */
  protected readonly isSystemAgent = computed(
    () => this.agent()?.name === 'system',
  );

  /** Status pill class — emerald-400 for active, subtle for retired. */
  protected readonly statusClass = computed(() => {
    const a = this.agent();
    if (!a) return 'text-fg-muted';
    return a.status === 'active' ? 'text-emerald-400' : 'text-fg-subtle';
  });

  protected onCopyAgentName(): void {
    this.justCopied.set(true);
    setTimeout(() => this.justCopied.set(false), 1500);
  }
}
