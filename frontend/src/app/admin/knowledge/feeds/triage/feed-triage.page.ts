import { DatePipe } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import type { FeedEntryRow } from '../../../../core/models/feed.model';
import { FeedService } from '../../../../core/services/feed.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

/**
 * Feed Triage Inbox-zero card flow:
 * show one entry at a time, `D` drafts / `I` ignores / `u` undoes the
 * last action. The spec prescribes two actions only (Draft + Ignore)
 * plus undo; relevance feedback is exposed inline as smaller buttons.
 *
 * Draft currently calls out to the Content Editor in a new tab once a
 * content row exists — the two-step curate flow (POST /contents →
 * POST /feed-entries/:id/curate) lands when a quick-create dialog is
 * available. For now Draft records a placeholder curate action that
 * will surface an "endpoint not yet wired" toast — safe to defer.
 */
@Component({
  selector: 'app-feed-triage-page',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './feed-triage.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class FeedTriagePageComponent {
  private readonly feedService = inject(FeedService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<FeedEntryRow[], void>({
    stream: () =>
      this.feedService.listEntries({
        status: 'unread',
        sort: 'relevance',
        perPage: 50,
      }),
  });

  protected readonly entries = computed(() => this.resource.value() ?? []);
  protected readonly total = computed(() => this.entries().length);
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly cursor = signal(0);
  protected readonly current = computed(
    () => this.entries()[this.cursor()] ?? null,
  );
  protected readonly remaining = computed(() =>
    Math.max(0, this.total() - this.cursor()),
  );

  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  /** Stack of "undoable" actions. Only the most recent pop is `u`. */
  private readonly undoStack = signal<{ entryId: string }[]>([]);

  constructor() {
    this.topbar.set({
      title: 'Feed triage',
      crumbs: ['Knowledge', 'Feeds', 'Triage'],
      actions: [
        {
          id: 'back-to-feeds',
          label: '← Feeds',
          kind: 'secondary',
          run: () => this.router.navigate(['/admin/knowledge/feeds']),
        },
      ],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected relevanceDots(score: number | null): string {
    if (score == null) return '';
    const rounded = Math.min(5, Math.max(0, Math.round(score * 5)));
    return '●'.repeat(rounded) + '○'.repeat(5 - rounded);
  }

  protected ignore(): void {
    const entry = this.current();
    if (!entry || this._isActioning()) return;

    this._isActioning.set(true);
    this.feedService.ignore(entry.id).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.undoStack.update((s) => [...s, { entryId: entry.id }]);
        this.advance();
      },
      error: () => {
        this._isActioning.set(false);
        this.notifications.error('Failed to ignore.');
      },
    });
  }

  /**
   * Open the source URL in a new tab. Drafting and the curate link
   * happen in Cowork; the entry stays `unread` on the backend until
   * a quick-create content dialog lands here.
   */
  protected openSource(): void {
    const entry = this.current();
    if (!entry) return;

    if (typeof window !== 'undefined') {
      window.open(entry.source_url, '_blank', 'noopener,noreferrer');
    }
    this.notifications.info(
      'Opened in a new tab. Entry stays unread — draft it in Cowork to curate.',
    );
  }

  protected feedback(dir: 'up' | 'down'): void {
    const entry = this.current();
    if (!entry || this._isActioning()) return;

    this._isActioning.set(true);
    this.feedService.feedback(entry.id, dir).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.notifications.success(
          dir === 'up' ? 'Marked relevant.' : 'Marked not relevant.',
        );
      },
      error: () => {
        this._isActioning.set(false);
        this.notifications.error('Failed to record feedback.');
      },
    });
  }

  /**
   * Client-side rewind only — re-examine the previous card. The
   * backend Ignore / Draft actions are NOT reversed (once a feed
   * entry is ignored, it stays ignored; once a URL is opened and
   * drafted externally, that's permanent). Labelled "Back" in the UI
   * so users don't expect transactional undo.
   *
   * describes an 8s revertible undo —
   * B; implementing it requires delaying the POST on the client which
   * changes the triage flow's timing model.
   */
  protected rewindLast(): void {
    const stack = this.undoStack();
    if (stack.length === 0) return;
    const last = stack[stack.length - 1];
    this.undoStack.update((s) => s.slice(0, -1));
    const idx = this.entries().findIndex((e) => e.id === last.entryId);
    if (idx < 0) {
      this.notifications.info('That entry is no longer in the queue.');
      return;
    }
    this.cursor.set(idx);
    this.notifications.info('Re-examining previous entry.');
  }

  private advance(): void {
    this.cursor.update((i) => Math.min(i + 1, this.entries().length));
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (isFormControl(event.target)) return;
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;

    if (event.key === 'd' || event.key === 'D') {
      event.preventDefault();
      this.openSource();
    } else if (event.key === 'i' || event.key === 'I') {
      event.preventDefault();
      this.ignore();
    } else if (event.key === 'u' || event.key === 'U') {
      event.preventDefault();
      this.rewindLast();
    }
  }
}

function isFormControl(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement ||
    target.isContentEditable
  );
}
