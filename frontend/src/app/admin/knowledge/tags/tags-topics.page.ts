import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed } from '@angular/core/rxjs-interop';
import type { Observable } from 'rxjs';
import { TagService, type AdminTag } from '../../../core/services/tag.service';
import { TopicService } from '../../../core/services/topic.service';
import { NotificationService } from '../../../core/services/notification.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { ModalComponent } from '../../../shared/components/modal/modal.component';

interface RenameState {
  kind: 'tag' | 'topic';
  id: string;
  name: string;
}

/**
 * Tags & topics management.
 *
 * Tags: canonical list, inline rename (PUT), and merge (POST merge —
 * moves every alias and content link to the target, then deletes the
 * source). The list endpoint exposes no per-tag usage counts.
 *
 * Topics: list with published-content counts, inline rename (PUT).
 * No merge endpoint exists for topics.
 */
@Component({
  selector: 'app-tags-topics-page',
  imports: [ModalComponent],
  templateUrl: './tags-topics.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class TagsTopicsPageComponent {
  private readonly tagService = inject(TagService);
  private readonly topicService = inject(TopicService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly tagsResource = rxResource<AdminTag[], void>({
    stream: () => this.tagService.list(),
  });
  protected readonly topicsResource = rxResource({
    stream: () => this.topicService.adminList(),
  });

  protected readonly tags = computed(() =>
    this.tagsResource.hasValue() ? this.tagsResource.value() : [],
  );
  protected readonly topics = computed(() =>
    this.topicsResource.hasValue() ? this.topicsResource.value() : [],
  );
  protected readonly tagsError = computed(
    () => this.tagsResource.status() === 'error',
  );
  protected readonly topicsError = computed(
    () => this.topicsResource.status() === 'error',
  );

  private readonly _busy = signal(false);
  protected readonly busy = this._busy.asReadonly();

  /** Row currently in inline-rename mode (one at a time, both panels). */
  protected readonly renaming = signal<RenameState | null>(null);

  protected readonly mergeOpen = signal(false);
  protected readonly mergeSourceId = signal('');
  protected readonly mergeTargetId = signal('');
  protected readonly canMerge = computed(() => {
    const source = this.mergeSourceId();
    const target = this.mergeTargetId();
    return source !== '' && target !== '' && source !== target;
  });

  constructor() {
    this.topbar.set({
      title: 'Tags & topics',
      crumbs: ['Knowledge', 'Tags & topics'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected startRename(kind: 'tag' | 'topic', id: string, name: string): void {
    this.renaming.set({ kind, id, name });
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
    const call: Observable<unknown> =
      edit.kind === 'tag'
        ? this.tagService.update(edit.id, { name })
        : this.topicService.adminUpdate(edit.id, { name });
    call.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this._busy.set(false);
        this.renaming.set(null);
        this.notifications.success(`Renamed to "${name}".`);
        this.reload(edit.kind);
      },
      error: () => {
        this._busy.set(false);
        this.notifications.error('Failed to rename.');
      },
    });
  }

  protected openMerge(): void {
    this.mergeSourceId.set('');
    this.mergeTargetId.set('');
    this.mergeOpen.set(true);
  }

  protected readSelect(event: Event): string {
    return (event.target as HTMLSelectElement).value;
  }

  protected submitMerge(): void {
    if (!this.canMerge() || this._busy()) return;

    this._busy.set(true);
    this.tagService
      .merge(this.mergeSourceId(), this.mergeTargetId())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result) => {
          this._busy.set(false);
          this.mergeOpen.set(false);
          this.notifications.success(
            `Merged: ${result.aliases_moved} aliases and ${result.content_tags_moved} content links moved.`,
          );
          this.reload('tag');
        },
        error: () => {
          this._busy.set(false);
          this.notifications.error('Failed to merge tags.');
        },
      });
  }

  protected isRenaming(kind: 'tag' | 'topic', id: string): boolean {
    const edit = this.renaming();
    return edit !== null && edit.kind === kind && edit.id === id;
  }

  private reload(kind: 'tag' | 'topic'): void {
    if (kind === 'tag') {
      this.tagsResource.reload();
    } else {
      this.topicsResource.reload();
    }
  }
}
