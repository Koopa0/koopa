import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Tags,
  Plus,
  Pencil,
  Trash2,
  Check,
  X,
  Link,
  RefreshCw,
  ArrowRight,
  Merge,
  Database,
} from 'lucide-angular';
import { TagAdminService } from '../../core/services/tag-admin.service';
import { NotificationService } from '../../core/services/notification.service';
import { DeleteConfirmDialogComponent } from '../shared/delete-confirm-dialog.component';
import {
  PageHeaderComponent,
  DataTableComponent,
  EmptyStateComponent,
  LoadingSpinnerComponent,
  StatusBadgeComponent,
  ModalComponent,
  FormFieldComponent,
} from '../../shared/components';
import type {
  ApiTag,
  ApiTagAlias,
  AliasMatchMethod,
  ApiCreateTagRequest,
  ApiUpdateTagRequest,
} from '../../core/models';

type ActiveTab = 'tags' | 'aliases';
type AliasFilter = 'all' | 'unmapped' | 'pending';

interface TagFormData {
  slug: string;
  name: string;
  parent_id: string | null;
  description: string;
}

interface DeleteTarget {
  id: string;
  label: string;
  type: 'tag' | 'alias';
}

const MATCH_METHOD_LABELS: Record<AliasMatchMethod, string> = {
  exact: 'Exact',
  case_insensitive: 'Case Insensitive',
  slug: 'Slug Match',
  manual: 'Manual',
  rejected: 'Rejected',
  unmapped: 'Unmapped',
};

const MATCH_METHOD_CLASSES: Record<AliasMatchMethod, string> = {
  exact: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
  case_insensitive: 'border-sky-800 bg-sky-900/30 text-sky-400',
  slug: 'border-amber-800 bg-amber-900/30 text-amber-400',
  manual: 'border-violet-800 bg-violet-900/30 text-violet-400',
  rejected: 'border-red-800 bg-red-900/30 text-red-400',
  unmapped: 'border-zinc-600 bg-zinc-800 text-zinc-400',
};

@Component({
  selector: 'app-tags',
  standalone: true,
  imports: [
    DatePipe,
    FormsModule,
    LucideAngularModule,
    DeleteConfirmDialogComponent,
    PageHeaderComponent,
    DataTableComponent,
    EmptyStateComponent,
    LoadingSpinnerComponent,
    StatusBadgeComponent,
    ModalComponent,
    FormFieldComponent,
  ],
  templateUrl: './tags.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TagsComponent implements OnInit {
  private readonly tagAdmin = inject(TagAdminService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  // ─── 共用狀態 ───
  protected readonly activeTab = signal<ActiveTab>('tags');
  protected readonly tags = signal<ApiTag[]>([]);
  protected readonly isLoading = signal(false);

  // ─── Tags tab ───
  protected readonly isTagDialogOpen = signal(false);
  protected readonly editingTagId = signal<string | null>(null);
  protected readonly tagForm = signal<TagFormData>({
    slug: '',
    name: '',
    parent_id: null,
    description: '',
  });
  protected readonly isSavingTag = signal(false);
  protected readonly tagSlugError = signal<string | null>(null);

  protected readonly rootTags = computed(() =>
    this.tags().filter((t) => t.parent_id === null),
  );

  /** 排序：root tags 先，每個 root 下面接它的 children */
  protected readonly sortedTags = computed(() => {
    const all = this.tags();
    const roots = all
      .filter((t) => t.parent_id === null)
      .sort((a, b) => a.name.localeCompare(b.name));
    const result: ApiTag[] = [];
    for (const root of roots) {
      result.push(root);
      const children = all
        .filter((t) => t.parent_id === root.id)
        .sort((a, b) => a.name.localeCompare(b.name));
      result.push(...children);
    }
    // orphan tags（parent_id 指向不存在的 tag）
    const ids = new Set(result.map((t) => t.id));
    const orphans = all.filter((t) => !ids.has(t.id));
    result.push(...orphans);
    return result;
  });

  // ─── Aliases tab ───
  protected readonly aliases = signal<ApiTagAlias[]>([]);
  protected readonly aliasFilter = signal<AliasFilter>('all');
  protected readonly isLoadingAliases = signal(false);

  protected readonly filteredAliases = computed(() => {
    const all = this.aliases();
    const f = this.aliasFilter();
    if (f === 'unmapped') {
      return all.filter((a) => a.tag_id === null);
    }
    if (f === 'pending') {
      return all.filter((a) => a.tag_id !== null && !a.confirmed);
    }
    return all;
  });

  protected readonly unmappedCount = computed(
    () => this.aliases().filter((a) => a.tag_id === null).length,
  );

  protected readonly pendingCount = computed(
    () =>
      this.aliases().filter((a) => a.tag_id !== null && !a.confirmed).length,
  );

  /** 追蹤每個 alias 正在選擇的 tag_id（for map dropdown） */
  protected readonly aliasMapSelections = signal<Record<string, string>>({});

  // ─── Merge dialog ───
  protected readonly isMergeDialogOpen = signal(false);
  protected readonly mergeSourceId = signal<string>('');
  protected readonly mergeTargetId = signal<string>('');
  protected readonly isMerging = signal(false);

  // ─── Backfill ───
  protected readonly isBackfilling = signal(false);

  // ─── 刪除 dialog ───
  protected readonly deleteTarget = signal<DeleteTarget | null>(null);
  protected readonly isDeleting = signal(false);

  // ─── Icons ───
  protected readonly TagsIcon = Tags;
  protected readonly PlusIcon = Plus;
  protected readonly PencilIcon = Pencil;
  protected readonly Trash2Icon = Trash2;
  protected readonly CheckIcon = Check;
  protected readonly XIcon = X;
  protected readonly LinkIcon = Link;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly MergeIcon = Merge;
  protected readonly DatabaseIcon = Database;

  ngOnInit(): void {
    this.loadTags();
  }

  // ─── Tab 切換 ───

  protected switchTab(tab: ActiveTab): void {
    this.activeTab.set(tab);
    if (tab === 'aliases' && this.aliases().length === 0) {
      this.loadAliases();
    }
  }

  // ─── Tags CRUD ───

  protected loadTags(): void {
    this.isLoading.set(true);
    this.tagAdmin
      .getTags()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.tags.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Tags');
          this.isLoading.set(false);
        },
      });
  }

  protected openCreateTagDialog(): void {
    this.editingTagId.set(null);
    this.tagForm.set({ slug: '', name: '', parent_id: null, description: '' });
    this.tagSlugError.set(null);
    this.isTagDialogOpen.set(true);
  }

  protected openEditTagDialog(tag: ApiTag): void {
    this.editingTagId.set(tag.id);
    this.tagForm.set({
      slug: tag.slug,
      name: tag.name,
      parent_id: tag.parent_id,
      description: tag.description,
    });
    this.tagSlugError.set(null);
    this.isTagDialogOpen.set(true);
  }

  protected closeTagDialog(): void {
    this.isTagDialogOpen.set(false);
  }

  protected updateTagFormField(
    field: keyof TagFormData,
    value: string | null,
  ): void {
    this.tagForm.update((f) => ({ ...f, [field]: value }));
    if (field === 'slug') {
      this.tagSlugError.set(null);
    }
  }

  protected saveTag(): void {
    const form = this.tagForm();
    if (!form.slug.trim() || !form.name.trim()) {
      return;
    }

    this.isSavingTag.set(true);
    const editId = this.editingTagId();

    if (editId) {
      const body: ApiUpdateTagRequest = {
        slug: form.slug.trim(),
        name: form.name.trim(),
        parent_id: form.parent_id || null,
        description: form.description.trim(),
      };
      this.tagAdmin
        .updateTag(editId, body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: (updated) => {
            this.tags.update((list) =>
              list.map((t) => (t.id === editId ? updated : t)),
            );
            this.isSavingTag.set(false);
            this.isTagDialogOpen.set(false);
            this.notificationService.success('Tag 已更新');
          },
          error: (err) => {
            this.isSavingTag.set(false);
            this.handleTagSaveError(err);
          },
        });
    } else {
      const body: ApiCreateTagRequest = {
        slug: form.slug.trim(),
        name: form.name.trim(),
        parent_id: form.parent_id || undefined,
        description: form.description.trim() || undefined,
      };
      this.tagAdmin
        .createTag(body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: (created) => {
            this.tags.update((list) => [...list, created]);
            this.isSavingTag.set(false);
            this.isTagDialogOpen.set(false);
            this.notificationService.success('Tag 已建立');
          },
          error: (err) => {
            this.isSavingTag.set(false);
            this.handleTagSaveError(err);
          },
        });
    }
  }

  protected requestDeleteTag(tag: ApiTag): void {
    this.deleteTarget.set({ id: tag.id, label: tag.name, type: 'tag' });
  }

  protected getParentName(parentId: string | null): string {
    if (!parentId) {
      return '—';
    }
    const parent = this.tags().find((t) => t.id === parentId);
    return parent ? parent.name : '—';
  }

  // ─── Aliases ───

  protected loadAliases(): void {
    this.isLoadingAliases.set(true);
    this.tagAdmin
      .getAliases()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.aliases.set(data);
          this.isLoadingAliases.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Aliases');
          this.isLoadingAliases.set(false);
        },
      });
  }

  protected setAliasFilter(f: AliasFilter): void {
    this.aliasFilter.set(f);
  }

  protected getMatchMethodLabel(method: AliasMatchMethod): string {
    return MATCH_METHOD_LABELS[method];
  }

  protected getMatchMethodClass(method: AliasMatchMethod): string {
    return MATCH_METHOD_CLASSES[method];
  }

  protected getTagName(tagId: string | null): string {
    if (!tagId) {
      return '';
    }
    const tag = this.tags().find((t) => t.id === tagId);
    return tag ? tag.name : tagId;
  }

  protected setAliasMapSelection(aliasId: string, tagId: string): void {
    this.aliasMapSelections.update((s) => ({ ...s, [aliasId]: tagId }));
  }

  protected mapAlias(alias: ApiTagAlias): void {
    const tagId = this.aliasMapSelections()[alias.id];
    if (!tagId) {
      return;
    }
    this.tagAdmin
      .mapAlias(alias.id, tagId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (updated) => {
          this.aliases.update((list) =>
            list.map((a) => (a.id === alias.id ? updated : a)),
          );
          this.aliasMapSelections.update((s) => {
            const copy = { ...s };
            delete copy[alias.id];
            return copy;
          });
          this.notificationService.success(`已映射 "${alias.raw_tag}"`);
        },
        error: () => this.notificationService.error('映射失敗'),
      });
  }

  protected confirmAlias(alias: ApiTagAlias): void {
    this.tagAdmin
      .confirmAlias(alias.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (updated) => {
          this.aliases.update((list) =>
            list.map((a) => (a.id === alias.id ? updated : a)),
          );
          this.notificationService.success(`已確認 "${alias.raw_tag}"`);
        },
        error: () => this.notificationService.error('確認失敗'),
      });
  }

  protected rejectAlias(alias: ApiTagAlias): void {
    this.tagAdmin
      .rejectAlias(alias.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (updated) => {
          this.aliases.update((list) =>
            list.map((a) => (a.id === alias.id ? updated : a)),
          );
          this.notificationService.success(`已拒絕 "${alias.raw_tag}"`);
        },
        error: () => this.notificationService.error('拒絕失敗'),
      });
  }

  protected requestDeleteAlias(alias: ApiTagAlias): void {
    this.deleteTarget.set({
      id: alias.id,
      label: alias.raw_tag,
      type: 'alias',
    });
  }

  // ─── Delete dialog ───

  protected cancelDelete(): void {
    this.deleteTarget.set(null);
  }

  protected confirmDelete(): void {
    const target = this.deleteTarget();
    if (!target) {
      return;
    }

    this.isDeleting.set(true);
    const obs =
      target.type === 'tag'
        ? this.tagAdmin.deleteTag(target.id)
        : this.tagAdmin.deleteAlias(target.id);

    obs.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        if (target.type === 'tag') {
          this.tags.update((list) => list.filter((t) => t.id !== target.id));
        } else {
          this.aliases.update((list) => list.filter((a) => a.id !== target.id));
        }
        this.deleteTarget.set(null);
        this.isDeleting.set(false);
        this.notificationService.success('已刪除');
      },
      error: (err) => {
        this.isDeleting.set(false);
        if (err?.status === 409) {
          this.notificationService.error(
            '此 Tag 仍有 alias 或筆記引用，請先處理',
          );
        } else {
          this.notificationService.error('刪除失敗');
        }
        this.deleteTarget.set(null);
      },
    });
  }

  // ─── Merge ───

  protected openMergeDialog(): void {
    this.mergeSourceId.set('');
    this.mergeTargetId.set('');
    this.isMergeDialogOpen.set(true);
  }

  protected closeMergeDialog(): void {
    this.isMergeDialogOpen.set(false);
  }

  protected executeMerge(): void {
    const sourceId = this.mergeSourceId();
    const targetId = this.mergeTargetId();
    if (!sourceId || !targetId || sourceId === targetId) {
      return;
    }

    this.isMerging.set(true);
    this.tagAdmin
      .mergeTags({ source_id: sourceId, target_id: targetId })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result) => {
          this.isMerging.set(false);
          this.isMergeDialogOpen.set(false);
          this.notificationService.success(
            `合併完成：${result.aliases_moved} aliases、${result.notes_moved} notes、${result.events_moved} events 已移轉`,
          );
          this.loadTags();
        },
        error: () => {
          this.isMerging.set(false);
          this.notificationService.error('合併失敗');
        },
      });
  }

  // ─── Backfill ───

  protected runBackfill(): void {
    this.isBackfilling.set(true);
    this.tagAdmin
      .backfillTags()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result) => {
          this.isBackfilling.set(false);
          this.notificationService.success(
            `回填完成：處理 ${result.notes_processed} 筆記、${result.tags_mapped} mapped、${result.tags_unmapped} unmapped`,
          );
          this.loadAliases();
        },
        error: () => {
          this.isBackfilling.set(false);
          this.notificationService.error('回填失敗');
        },
      });
  }

  // ─── Private ───

  private handleTagSaveError(err: { status?: number }): void {
    if (err?.status === 409) {
      this.tagSlugError.set('此 slug 已存在');
    } else {
      this.notificationService.error('儲存失敗');
    }
  }
}
