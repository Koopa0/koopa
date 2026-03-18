import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Brain,
  RefreshCw,
  Loader2,
  ChevronRight,
  BookOpen,
  Clock,
  Plus,
} from 'lucide-angular';
import { SpacedService } from '../../core/services/spaced.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiDueInterval } from '../../core/models';

interface QualityOption {
  value: number;
  label: string;
  emoji: string;
  description: string;
  buttonClass: string;
}

const QUALITY_OPTIONS: QualityOption[] = [
  { value: 0, label: '完全不記得', emoji: '😵', description: 'Blackout', buttonClass: 'border-red-800 bg-red-900/30 text-red-400 hover:bg-red-900/50' },
  { value: 1, label: '看到才想起', emoji: '😟', description: 'Wrong', buttonClass: 'border-orange-800 bg-orange-900/30 text-orange-400 hover:bg-orange-900/50' },
  { value: 2, label: '快想起來了', emoji: '😐', description: 'Almost', buttonClass: 'border-amber-800 bg-amber-900/30 text-amber-400 hover:bg-amber-900/50' },
  { value: 3, label: '正確但費力', emoji: '🤔', description: 'Hard', buttonClass: 'border-yellow-800 bg-yellow-900/30 text-yellow-400 hover:bg-yellow-900/50' },
  { value: 4, label: '稍有猶豫', emoji: '😊', description: 'Good', buttonClass: 'border-emerald-800 bg-emerald-900/30 text-emerald-400 hover:bg-emerald-900/50' },
  { value: 5, label: '完美', emoji: '🎯', description: 'Perfect', buttonClass: 'border-sky-800 bg-sky-900/30 text-sky-400 hover:bg-sky-900/50' },
];

@Component({
  selector: 'app-spaced',
  standalone: true,
  imports: [DatePipe, DecimalPipe, FormsModule, LucideAngularModule],
  templateUrl: './spaced.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SpacedComponent implements OnInit {
  private readonly spacedService = inject(SpacedService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly dueItems = signal<ApiDueInterval[]>([]);
  protected readonly totalDue = signal(0);
  protected readonly isLoading = signal(false);
  protected readonly isSubmitting = signal(false);

  // ─── Enroll ───
  protected readonly isEnrollDialogOpen = signal(false);
  protected readonly enrollNoteId = signal('');
  protected readonly isEnrolling = signal(false);

  /** 目前正在複習的 index */
  protected readonly currentIndex = signal(0);

  /** 是否顯示答案（翻牌狀態） */
  protected readonly isRevealed = signal(false);

  protected readonly currentItem = computed(() => {
    const items = this.dueItems();
    const idx = this.currentIndex();
    return idx < items.length ? items[idx] : null;
  });

  protected readonly progress = computed(() => {
    const total = this.dueItems().length;
    const current = this.currentIndex();
    return total > 0 ? Math.round((current / total) * 100) : 0;
  });

  protected readonly remainingCount = computed(
    () => this.dueItems().length - this.currentIndex(),
  );

  protected readonly qualityOptions = QUALITY_OPTIONS;

  // ─── Icons ───
  protected readonly BrainIcon = Brain;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly Loader2Icon = Loader2;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly BookOpenIcon = BookOpen;
  protected readonly ClockIcon = Clock;
  protected readonly PlusIcon = Plus;

  ngOnInit(): void {
    this.loadDue();
  }

  protected loadDue(): void {
    this.isLoading.set(true);
    this.currentIndex.set(0);
    this.isRevealed.set(false);
    this.spacedService
      .listDue()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.dueItems.set(response.intervals);
          this.totalDue.set(response.total_due);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入複習項目');
          this.isLoading.set(false);
        },
      });
  }

  protected reveal(): void {
    this.isRevealed.set(true);
  }

  protected submitReview(quality: number): void {
    const item = this.currentItem();
    if (!item || this.isSubmitting()) {
      return;
    }

    this.isSubmitting.set(true);
    this.spacedService
      .submitReview({ note_id: item.note_id, quality })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (updated) => {
          this.isSubmitting.set(false);
          this.isRevealed.set(false);
          const nextDays = updated.interval_days;
          this.notificationService.success(
            `下次複習：${nextDays} 天後`,
          );
          this.currentIndex.update((i) => i + 1);
        },
        error: () => {
          this.isSubmitting.set(false);
          this.notificationService.error('提交失敗');
        },
      });
  }

  protected skipItem(): void {
    this.isRevealed.set(false);
    this.currentIndex.update((i) => i + 1);
  }

  // ─── Enroll ───

  protected openEnrollDialog(): void {
    this.enrollNoteId.set('');
    this.isEnrollDialogOpen.set(true);
  }

  protected closeEnrollDialog(): void {
    this.isEnrollDialogOpen.set(false);
  }

  protected enrollNote(): void {
    const noteIdStr = this.enrollNoteId().trim();
    const noteId = parseInt(noteIdStr, 10);
    if (isNaN(noteId) || noteId <= 0) {
      this.notificationService.error('請輸入有效的 Note ID');
      return;
    }

    this.isEnrolling.set(true);
    this.spacedService
      .enroll({ note_id: noteId })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isEnrolling.set(false);
          this.isEnrollDialogOpen.set(false);
          this.notificationService.success(`Note #${noteId} 已加入複習系統`);
          this.loadDue();
        },
        error: (err) => {
          this.isEnrolling.set(false);
          if (err?.status === 409) {
            this.notificationService.error('此筆記已在複習系統中');
          } else {
            this.notificationService.error('加入失敗');
          }
        },
      });
  }

  /** 從 file_path 提取檔名 */
  protected getFileName(filePath: string): string {
    const parts = filePath.split('/');
    const name = parts[parts.length - 1];
    return name.replace(/\.md$/, '');
  }
}
