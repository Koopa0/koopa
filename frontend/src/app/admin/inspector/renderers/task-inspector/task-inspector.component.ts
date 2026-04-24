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
import { TaskService } from '../../../../core/services/task.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { InspectorService } from '../../inspector.service';
import type {
  CoordinationTask,
  TaskMessage,
  Artifact,
} from '../../../../core/models/workbench.model';

type TaskTab = 'overview' | 'thread' | 'artifacts';

/**
 * Task Inspector renderer — Overview + Thread + Artifacts tabs.
 *
 * Action bar is state-dependent:
 *   completed (unreviewed) → Approve / Reply / Request Revision
 *   revision_requested    → read-only "Waiting for {agent}"
 *   working               → read-only "{agent} is working"
 */
@Component({
  selector: 'app-task-inspector',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './task-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TaskInspectorComponent {
  readonly id = input.required<string>();

  private readonly taskService = inject(TaskService);
  private readonly inspector = inject(InspectorService);
  private readonly notifications = inject(NotificationService);

  protected readonly activeTab = signal<TaskTab>('overview');
  protected readonly isActioning = signal(false);
  protected readonly replyText = signal('');
  protected readonly isReplyExpanded = signal(false);

  protected readonly taskResource = rxResource<CoordinationTask, string>({
    params: () => this.id(),
    stream: ({ params }) => this.taskService.get(params),
  });

  protected readonly messagesResource = rxResource<TaskMessage[], string>({
    params: () => this.id(),
    stream: ({ params }) => this.taskService.messages(params),
  });

  protected readonly artifactsResource = rxResource<Artifact[], string>({
    params: () => this.id(),
    stream: ({ params }) => this.taskService.artifacts(params),
  });

  protected readonly task = this.taskResource.value;
  protected readonly messages = computed(
    () => this.messagesResource.value() ?? [],
  );
  protected readonly artifacts = computed(
    () => this.artifactsResource.value() ?? [],
  );
  protected readonly isLoading = computed(
    () => this.taskResource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.taskResource.status() === 'error',
  );

  protected readonly isReviewable = computed(() => {
    return this.task()?.state === 'completed';
  });

  protected readonly isWaiting = computed(() => {
    const state = this.task()?.state;
    return state === 'revision_requested' || state === 'working';
  });

  protected readonly statusMessage = computed(() => {
    const t = this.task();
    if (!t) return '';
    switch (t.state) {
      case 'revision_requested':
        return `Waiting for ${t.target}`;
      case 'working':
        return `${t.target} is working`;
      case 'submitted':
        return `Submitted to ${t.target}`;
      default:
        return '';
    }
  });

  protected setTab(tab: TaskTab): void {
    this.activeTab.set(tab);
  }

  protected approve(): void {
    const t = this.task();
    if (!t || this.isActioning()) return;

    // "Approve" = mark as reviewed. For now, just record the action.
    this.inspector.recordAction('task', t.id, 'approve');
    this.notifications.success(`Approved "${t.title}"`);
  }

  protected toggleReply(): void {
    this.isReplyExpanded.update((v) => !v);
  }

  protected sendReply(): void {
    const t = this.task();
    const text = this.replyText().trim();
    if (!t || !text || this.isActioning()) return;

    this.isActioning.set(true);
    this.taskService.reply(t.id, text).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.replyText.set('');
        this.isReplyExpanded.set(false);
        this.messagesResource.reload();
        this.notifications.success('Reply sent.');
      },
      error: () => {
        this.isActioning.set(false);
        this.notifications.error('Failed to send reply.');
      },
    });
  }

  protected requestRevision(): void {
    const t = this.task();
    if (!t || this.isActioning()) return;

    this.isActioning.set(true);
    this.taskService.requestRevision(t.id).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.taskResource.reload();
        this.inspector.recordAction('task', t.id, 'request_revision');
        this.notifications.success(`Revision requested for "${t.title}"`);
      },
      error: () => {
        this.isActioning.set(false);
        this.notifications.error('Failed to request revision.');
      },
    });
  }

  protected readTextarea(event: Event): string {
    return (event.target as HTMLTextAreaElement).value;
  }
}
