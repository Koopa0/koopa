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
import { RouterLink } from '@angular/router';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { LucideAngularModule, Copy as CopyIcon } from 'lucide-angular';
import { AgentService } from '../../../../core/services/agent.service';
import type { AgentDetail } from '../../../../core/models/workbench.model';

/**
 * Agent Inspector renderer — identity card (v1 brief).
 *
 * Design intent (frontend/docs/inspector-design/agent-inspector.md):
 * - Agent has even less depth than Todo. Single tab, ~6-10 rows.
 * - Capability is a Go compile-time gate (NOT in DB) — render as plain text inline,
 *   not a permissions matrix dot grid.
 * - Schedule: human-readable default, raw cron in <details> progressive disclosure.
 * - NO embedded task list.
 *   Single tail link → Atlas filtered by assignee=name.
 * - NO action buttons — agents are hardcoded code change, not workbench-mutable.
 * - `system` agent gets amber warning (hidden fallback identity per Fact 9).
 *
 * Backend: GET /api/admin/coordination/agents/{name}.
 */
@Component({
  selector: 'app-agent-inspector',
  standalone: true,
  imports: [DatePipe, ClipboardModule, RouterLink, LucideAngularModule],
  templateUrl: './agent-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AgentInspectorComponent {
  readonly id = input.required<string>();

  private readonly agentService = inject(AgentService);

  protected readonly justCopied = signal(false);
  protected readonly CopyIcon = CopyIcon;

  protected readonly resource = rxResource<AgentDetail, string>({
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

  /**
   * Capability inline plain text per Fact 2: "submits tasks · receives tasks · publishes artifacts".
   * Returns null when ALL capabilities false (passive identity like koopa0-dev/go-spec/claude/system).
   */
  protected readonly capabilityText = computed(() => {
    const a = this.agent();
    if (!a) return null;
    const parts: string[] = [];
    if (a.capability.submit_tasks) parts.push('submits tasks');
    if (a.capability.receive_tasks) parts.push('receives tasks');
    if (a.capability.publish_artifacts) parts.push('publishes artifacts');
    return parts.length > 0 ? parts.join(' · ') : null;
  });

  /**
   * Schedule text — prefer server-derived human_readable; fallback to raw purpose.
   * Returns null when no schedule.
   */
  protected readonly scheduleText = computed(() => {
    const a = this.agent();
    if (!a?.schedule) return null;
    if (a.schedule_human_readable) return a.schedule_human_readable;
    if (a.schedule.purpose) return a.schedule.purpose;
    return null;
  });

  /** True when agent is the hidden `system` fallback (Fact 9 — surface warning). */
  protected readonly isSystemAgent = computed(
    () => this.agent()?.name === 'system',
  );

  /** Status pill class — emerald-400 for active, zinc-500 for retired. */
  protected readonly statusClass = computed(() => {
    const a = this.agent();
    if (!a) return 'text-zinc-400';
    return a.status === 'active' ? 'text-emerald-400' : 'text-zinc-500';
  });

  protected onCopyAgentName(): void {
    this.justCopied.set(true);
    setTimeout(() => this.justCopied.set(false), 1500);
  }
}
