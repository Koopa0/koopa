import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TopicService } from '../../../core/services/topic.service';
import { NotificationService } from '../../../core/services/notification.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

interface RenameState {
  id: string;
  name: string;
}

/**
 * Topics management.
 *
 * Topics: list with published-content counts, inline rename (PUT). No
 * merge endpoint exists for topics.
 */
@Component({
  selector: 'app-topics-page',
  templateUrl: './topics.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class TopicsPageComponent {
  private readonly topicService = inject(TopicService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly topicsResource = rxResource({
    stream: () => this.topicService.adminList(),
  });

  protected readonly topics = computed(() =>
    this.topicsResource.hasValue() ? this.topicsResource.value() : [],
  );
  protected readonly topicsError = computed(
    () => this.topicsResource.status() === 'error',
  );

  private readonly _busy = signal(false);
  protected readonly busy = this._busy.asReadonly();

  /** Row currently in inline-rename mode (one at a time). */
  protected readonly renaming = signal<RenameState | null>(null);

  constructor() {
    this.topbar.set({
      title: 'Topics',
      crumbs: ['Knowledge', 'Topics'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected startRename(id: string, name: string): void {
    this.renaming.set({ id, name });
  }

  protected setRenameValue(event: Event): void {
    const name = (event.target as HTMLInputElement).value;
    this.renaming.update((r) => (r ? { ...r, name } : r));
  }

  protected cancelRename(): void {
    this.renaming.set(null);
  }

  protected commitRename(): void {
    const edit = this.renaming();
    if (!edit || this._busy()) return;
    const name = edit.name.trim();
    if (name === '') {
      this.cancelRename();
      return;
    }

    this._busy.set(true);
    this.topicService
      .adminUpdate(edit.id, { name })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._busy.set(false);
          this.renaming.set(null);
          this.notifications.success(`Renamed to "${name}".`);
          this.topicsResource.reload();
        },
        error: () => {
          this._busy.set(false);
          this.notifications.error('Failed to rename.');
        },
      });
  }

  protected isRenaming(id: string): boolean {
    const edit = this.renaming();
    return edit !== null && edit.id === id;
  }
}
