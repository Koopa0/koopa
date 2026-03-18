import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Database,
  Plus,
  Pencil,
  Trash2,
  Loader2,
  RefreshCw,
  X,
} from 'lucide-angular';
import { NotionSourceService } from '../../core/services/notion-source.service';
import { NotificationService } from '../../core/services/notification.service';
import { DeleteConfirmDialogComponent } from '../shared/delete-confirm-dialog.component';
import type {
  ApiNotionSource,
  ApiCreateNotionSourceRequest,
  ApiUpdateNotionSourceRequest,
  ApiDiscoveredDatabase,
  NotionSyncMode,
  NotionPollInterval,
} from '../../core/models';

type DialogMode = 'create' | 'edit';

interface SourceFormData {
  database_id: string;
  name: string;
  description: string;
  sync_mode: NotionSyncMode;
  poll_interval: NotionPollInterval;
}

const POLL_INTERVAL_OPTIONS: NotionPollInterval[] = [
  '5 minutes',
  '10 minutes',
  '15 minutes',
  '30 minutes',
  '1 hour',
  '2 hours',
  '4 hours',
  '6 hours',
  '12 hours',
  '24 hours',
];

const EMPTY_FORM: SourceFormData = {
  database_id: '',
  name: '',
  description: '',
  sync_mode: 'full',
  poll_interval: '15 minutes',
};

@Component({
  selector: 'app-notion-sources',
  standalone: true,
  imports: [
    DatePipe,
    FormsModule,
    LucideAngularModule,
    DeleteConfirmDialogComponent,
  ],
  templateUrl: './notion-sources.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NotionSourcesComponent implements OnInit {
  private readonly sourceService = inject(NotionSourceService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly sources = signal<ApiNotionSource[]>([]);
  protected readonly isLoading = signal(false);

  // ─── Discover ───
  protected readonly discoveredDatabases = signal<ApiDiscoveredDatabase[]>([]);
  protected readonly isDiscovering = signal(false);

  // ─── Dialog ───
  protected readonly isDialogOpen = signal(false);
  protected readonly dialogMode = signal<DialogMode>('create');
  protected readonly editingId = signal<string | null>(null);
  protected readonly form = signal<SourceFormData>({ ...EMPTY_FORM });
  protected readonly isSaving = signal(false);

  // ─── Delete ───
  protected readonly deleteTarget = signal<{ id: string; name: string } | null>(null);
  protected readonly isDeleting = signal(false);

  // ─── Constants ───
  protected readonly pollIntervalOptions = POLL_INTERVAL_OPTIONS;

  // ─── Icons ───
  protected readonly DatabaseIcon = Database;
  protected readonly PlusIcon = Plus;
  protected readonly PencilIcon = Pencil;
  protected readonly Trash2Icon = Trash2;
  protected readonly Loader2Icon = Loader2;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly XIcon = X;

  ngOnInit(): void {
    this.loadSources();
  }

  protected loadSources(): void {
    this.isLoading.set(true);
    this.sourceService
      .list()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.sources.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Notion Sources');
          this.isLoading.set(false);
        },
      });
  }

  // ─── Dialog ───

  protected openCreateDialog(): void {
    this.dialogMode.set('create');
    this.editingId.set(null);
    this.form.set({ ...EMPTY_FORM });
    this.isDialogOpen.set(true);
    this.loadDiscoveredDatabases();
  }

  private loadDiscoveredDatabases(): void {
    this.isDiscovering.set(true);
    this.sourceService
      .discover()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (dbs) => {
          this.discoveredDatabases.set(dbs);
          this.isDiscovering.set(false);
        },
        error: () => {
          this.discoveredDatabases.set([]);
          this.isDiscovering.set(false);
        },
      });
  }

  protected onDiscoverSelect(dbId: string): void {
    const db = this.discoveredDatabases().find((d) => d.id === dbId);
    if (db) {
      this.form.update((f) => ({
        ...f,
        database_id: db.id,
        name: f.name || db.title,
      }));
    }
  }

  protected openEditDialog(source: ApiNotionSource): void {
    this.dialogMode.set('edit');
    this.editingId.set(source.id);
    this.form.set({
      database_id: source.database_id,
      name: source.name,
      description: source.description,
      sync_mode: source.sync_mode,
      poll_interval: source.poll_interval as NotionPollInterval,
    });
    this.isDialogOpen.set(true);
  }

  protected closeDialog(): void {
    this.isDialogOpen.set(false);
  }

  protected updateFormField(field: keyof SourceFormData, value: string): void {
    this.form.update((f) => ({ ...f, [field]: value }));
  }

  protected saveSource(): void {
    const f = this.form();
    if (!f.database_id.trim() || !f.name.trim()) {
      return;
    }

    this.isSaving.set(true);
    const editId = this.editingId();

    if (editId) {
      const body: ApiUpdateNotionSourceRequest = {
        name: f.name.trim(),
        description: f.description.trim() || undefined,
        sync_mode: f.sync_mode,
        poll_interval: f.poll_interval,
      };
      this.sourceService
        .update(editId, body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: (updated) => {
            this.sources.update((list) =>
              list.map((s) => (s.id === editId ? updated : s)),
            );
            this.isSaving.set(false);
            this.isDialogOpen.set(false);
            this.notificationService.success('已更新');
          },
          error: () => {
            this.isSaving.set(false);
            this.notificationService.error('更新失敗');
          },
        });
    } else {
      const body: ApiCreateNotionSourceRequest = {
        database_id: f.database_id.trim(),
        name: f.name.trim(),
        description: f.description.trim() || undefined,
        sync_mode: f.sync_mode,
        poll_interval: f.poll_interval,
      };
      this.sourceService
        .create(body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: (created) => {
            this.sources.update((list) => [...list, created]);
            this.isSaving.set(false);
            this.isDialogOpen.set(false);
            this.notificationService.success('已建立');
          },
          error: () => {
            this.isSaving.set(false);
            this.notificationService.error('建立失敗');
          },
        });
    }
  }

  // ─── Toggle ───

  protected toggleSource(source: ApiNotionSource): void {
    this.sourceService
      .toggle(source.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (updated) => {
          this.sources.update((list) =>
            list.map((s) => (s.id === source.id ? updated : s)),
          );
          this.notificationService.success(
            updated.enabled ? '已啟用' : '已停用',
          );
        },
        error: () => this.notificationService.error('切換失敗'),
      });
  }

  // ─── Delete ───

  protected requestDelete(source: ApiNotionSource): void {
    this.deleteTarget.set({ id: source.id, name: source.name });
  }

  protected cancelDelete(): void {
    this.deleteTarget.set(null);
  }

  protected confirmDelete(): void {
    const target = this.deleteTarget();
    if (!target) {
      return;
    }

    this.isDeleting.set(true);
    this.sourceService
      .delete(target.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.sources.update((list) => list.filter((s) => s.id !== target.id));
          this.deleteTarget.set(null);
          this.isDeleting.set(false);
          this.notificationService.success('已刪除');
        },
        error: () => {
          this.isDeleting.set(false);
          this.notificationService.error('刪除失敗');
          this.deleteTarget.set(null);
        },
      });
  }
}
