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
import { ActivatedRoute, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map } from 'rxjs';
import { TaskService } from '../../../../core/services/task.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  A2aPart,
  Artifact,
  CoordinationTask,
  TaskMessage,
  TaskState,
} from '../../../../core/models/workbench.model';
import { isTextPart } from '../../../../core/models/workbench.model';

const STATE_DOT_CLASS: Record<TaskState, string> = {
  submitted: 'bg-zinc-400',
  working: 'bg-sky-400',
  revision_requested: 'bg-amber-400',
  completed: 'bg-emerald-500',
  canceled: 'bg-zinc-600',
};

const STATE_LABEL: Record<TaskState, string> = {
  submitted: 'submitted',
  working: 'working',
  revision_requested: 'revision',
  completed: 'completed',
  canceled: 'canceled',
};

/**
 * Task Timeline. Renders the a2a message stream (`{text} | {data}`
 * parts), an artifact side rail, and a state-aware action bar
 * (Reply / Request revision / Approve / Cancel).
 */
@Component({
  selector: 'app-task-timeline-page',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './task-timeline.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class TaskTimelinePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly taskService = inject(TaskService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly taskResource = rxResource<CoordinationTask, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.taskService.get(params),
  });

  protected readonly messagesResource = rxResource<TaskMessage[], string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.taskService.messages(params),
  });

  protected readonly artifactsResource = rxResource<Artifact[], string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.taskService.artifacts(params),
  });

  protected readonly task = computed(() => this.taskResource.value());
  protected readonly messages = computed(
    () => this.messagesResource.value() ?? [],
  );
  protected readonly artifacts = computed(
    () => this.artifactsResource.value() ?? [],
  );
  protected readonly isLoading = computed(
    () => this.taskResource.status() === 'loading' && !this.task(),
  );
  protected readonly hasError = computed(
    () => this.taskResource.status() === 'error',
  );

  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  protected readonly replyDraft = signal('');

  protected readonly canReply = computed(() => {
    const t = this.task();
    return (
      !!t &&
      (t.state === 'submitted' ||
        t.state === 'working' ||
        t.state === 'revision_requested')
    );
  });

  // Request-revision is only valid once the task is completed: the
  // human has the artifact in hand and wants to push back. Widen this
  // gate only if the backend policy changes.
  protected readonly canRequestRevision = computed(() => {
    const t = this.task();
    return !!t && t.state === 'completed';
  });

  protected readonly canApprove = computed(() => {
    const t = this.task();
    return !!t && t.state === 'completed';
  });

  // Cancel ends the task without a response message. Valid for
  // submitted / working / revision_requested; a completed task can be
  // re-opened via Request revision instead.
  protected readonly canCancel = computed(() => {
    const t = this.task();
    return (
      !!t &&
      (t.state === 'submitted' ||
        t.state === 'working' ||
        t.state === 'revision_requested')
    );
  });

  /**
   * Short hint describing how the draft textarea's contents will be
   * used once an action button is pressed. Keeps the multi-purpose
   * textarea honest when the task state changes.
   */
  protected readonly draftPlaceholder = computed(() => {
    const t = this.task();
    if (!t) return 'Write a reply…';
    switch (t.state) {
      case 'completed':
        return 'Optional: approval notes, or a revision reason if you push back';
      case 'revision_requested':
        return 'Write a reply, or leave empty and press Cancel task to close';
      case 'submitted':
      case 'working':
        return 'Write a reply, or a cancel reason';
      case 'canceled':
        return 'Task is canceled — no further action';
    }
  });

  constructor() {
    // Seed the topbar once synchronously so the crumbs are present on
    // the initial render. The effect below takes over once the task
    // arrives and skips null values so reloads don't flicker the
    // title back to the generic label.
    this.topbar.set({
      title: 'Task',
      crumbs: ['Coordination', 'Tasks'],
    });
    effect(() => {
      const t = this.task();
      if (!t) return;
      this.topbar.set({
        title: `Task · ${t.title}`,
        crumbs: ['Coordination', 'Tasks', t.id.slice(0, 8)],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected readTextarea(event: Event): string {
    return (event.target as HTMLTextAreaElement).value;
  }

  protected stateDotClass(state: TaskState): string {
    return STATE_DOT_CLASS[state];
  }

  protected stateLabel(state: TaskState): string {
    return STATE_LABEL[state];
  }

  protected textFromPart(part: A2aPart): string {
    return isTextPart(part) ? part.text : '';
  }

  protected dataMime(part: A2aPart): string | null {
    return isTextPart(part) ? null : part.data.mimeType;
  }

  protected back(): void {
    this.router.navigate(['/admin/coordination/tasks']);
  }

  protected reply(): void {
    const t = this.task();
    const text = this.replyDraft().trim();
    if (!t || !text || this._isActioning()) return;

    this._isActioning.set(true);
    this.taskService.reply(t.id, text).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.replyDraft.set('');
        this.notifications.success('Reply sent.');
        this.messagesResource.reload();
      },
      error: () => {
        this._isActioning.set(false);
        this.notifications.error('Failed to send reply.');
      },
    });
  }

  protected requestRevision(): void {
    const t = this.task();
    if (!t || this._isActioning()) return;
    const reason = this.replyDraft().trim();

    this._isActioning.set(true);
    this.taskService.requestRevision(t.id, reason || undefined).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.replyDraft.set('');
        this.notifications.success('Revision requested.');
        this.taskResource.reload();
        this.messagesResource.reload();
      },
      error: () => {
        this._isActioning.set(false);
        this.notifications.error('Failed to request revision.');
      },
    });
  }

  protected approve(): void {
    const t = this.task();
    if (!t || this._isActioning()) return;
    const notes = this.replyDraft().trim();

    this._isActioning.set(true);
    this.taskService.approve(t.id, notes || undefined).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.replyDraft.set('');
        this.notifications.success(`Approved "${t.title}".`);
        this.taskResource.reload();
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        this.handleMissingEndpoint(err, 'approve');
      },
    });
  }

  protected cancel(): void {
    const t = this.task();
    if (!t || this._isActioning()) return;
    const reason = this.replyDraft().trim();

    this._isActioning.set(true);
    this.taskService.cancel(t.id, reason || undefined).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.replyDraft.set('');
        this.notifications.success(`Canceled "${t.title}".`);
        this.taskResource.reload();
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        this.handleMissingEndpoint(err, 'cancel');
      },
    });
  }

  private handleMissingEndpoint(err: unknown, name: string): void {
    const status = err instanceof HttpErrorResponse ? err.status : null;
    if (status === 404 || status === 405 || status === 501) {
      this.notifications.info(
        `Endpoint not yet available in backend (${name}).`,
      );
      return;
    }
    this.notifications.error(`Failed to ${name}.`);
  }
}
