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
  Radar,
  Plus,
  Pencil,
  Trash2,
  Loader2,
  RefreshCw,
  X,
} from 'lucide-angular';
import { TrackingService } from '../../core/services/tracking.service';
import { NotificationService } from '../../core/services/notification.service';
import { DeleteConfirmDialogComponent } from '../shared/delete-confirm-dialog.component';
import type {
  ApiTrackingTopic,
  ApiCreateTrackingTopicRequest,
  ApiUpdateTrackingTopicRequest,
} from '../../core/models';

type DialogMode = 'create' | 'edit';

interface TopicFormData {
  name: string;
  keywords: string;
  sources: string;
  schedule: string;
  enabled: boolean;
}

const EMPTY_FORM: TopicFormData = {
  name: '',
  keywords: '',
  sources: '',
  schedule: 'daily',
  enabled: true,
};

const SCHEDULE_OPTIONS = [
  { value: 'hourly_4', label: 'Every 4h' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
];

@Component({
  selector: 'app-tracking',
  standalone: true,
  imports: [
    DatePipe,
    FormsModule,
    LucideAngularModule,
    DeleteConfirmDialogComponent,
  ],
  templateUrl: './tracking.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TrackingComponent implements OnInit {
  private readonly trackingService = inject(TrackingService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly topics = signal<ApiTrackingTopic[]>([]);
  protected readonly isLoading = signal(false);

  // ─── Dialog ───
  protected readonly isDialogOpen = signal(false);
  protected readonly dialogMode = signal<DialogMode>('create');
  protected readonly editingId = signal<string | null>(null);
  protected readonly form = signal<TopicFormData>({ ...EMPTY_FORM });
  protected readonly isSaving = signal(false);

  // ─── Delete ───
  protected readonly deleteTarget = signal<{ id: string; name: string } | null>(null);
  protected readonly isDeleting = signal(false);

  // ─── Constants ───
  protected readonly scheduleOptions = SCHEDULE_OPTIONS;

  // ─── Icons ───
  protected readonly RadarIcon = Radar;
  protected readonly PlusIcon = Plus;
  protected readonly PencilIcon = Pencil;
  protected readonly Trash2Icon = Trash2;
  protected readonly Loader2Icon = Loader2;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly XIcon = X;

  ngOnInit(): void {
    this.loadTopics();
  }

  protected loadTopics(): void {
    this.isLoading.set(true);
    this.trackingService
      .list()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.topics.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Tracking Topics');
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
  }

  protected openEditDialog(topic: ApiTrackingTopic): void {
    this.dialogMode.set('edit');
    this.editingId.set(topic.id);
    this.form.set({
      name: topic.name,
      keywords: topic.keywords.join(', '),
      sources: topic.sources.join(', '),
      schedule: topic.schedule,
      enabled: topic.enabled,
    });
    this.isDialogOpen.set(true);
  }

  protected closeDialog(): void {
    this.isDialogOpen.set(false);
  }

  protected updateFormField(field: keyof TopicFormData, value: string | boolean): void {
    this.form.update((f) => ({ ...f, [field]: value }));
  }

  protected saveTopic(): void {
    const f = this.form();
    if (!f.name.trim()) {
      return;
    }

    const parseList = (str: string): string[] =>
      str.split(',').map((s) => s.trim()).filter(Boolean);

    this.isSaving.set(true);
    const editId = this.editingId();

    if (editId) {
      const body: ApiUpdateTrackingTopicRequest = {
        name: f.name.trim(),
        keywords: parseList(f.keywords),
        sources: parseList(f.sources),
        schedule: f.schedule,
        enabled: f.enabled,
      };
      this.trackingService
        .update(editId, body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: (updated) => {
            this.topics.update((list) =>
              list.map((t) => (t.id === editId ? updated : t)),
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
      const body: ApiCreateTrackingTopicRequest = {
        name: f.name.trim(),
        keywords: parseList(f.keywords),
        sources: parseList(f.sources),
        schedule: f.schedule,
        enabled: f.enabled,
      };
      this.trackingService
        .create(body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: (created) => {
            this.topics.update((list) => [...list, created]);
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

  // ─── Delete ───

  protected requestDelete(topic: ApiTrackingTopic): void {
    this.deleteTarget.set({ id: topic.id, name: topic.name });
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
    this.trackingService
      .delete(target.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.topics.update((list) => list.filter((t) => t.id !== target.id));
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

  protected getScheduleLabel(schedule: string): string {
    return SCHEDULE_OPTIONS.find((o) => o.value === schedule)?.label ?? schedule;
  }
}
