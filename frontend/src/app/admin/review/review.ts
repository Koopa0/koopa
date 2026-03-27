import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  ClipboardCheck,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  Eye,
  MessageSquare,
  X,
} from 'lucide-angular';
import { ReviewService } from '../../core/services/review.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiReviewItem, ReviewLevel, ContentType } from '../../core/models';
import { contentTypeLabelEn } from '../../core/models';

const REVIEW_LEVEL_CONFIG: Record<ReviewLevel, { label: string; classes: string }> = {
  auto: { label: '自動', classes: 'border-zinc-600 bg-zinc-800 text-zinc-300' },
  light: { label: '輕度', classes: 'border-sky-700 bg-sky-900/30 text-sky-400' },
  standard: { label: '標準', classes: 'border-amber-700 bg-amber-900/30 text-amber-400' },
  strict: { label: '嚴格', classes: 'border-red-700 bg-red-900/30 text-red-400' },
};

@Component({
  selector: 'app-review',
  standalone: true,
  imports: [DatePipe, RouterLink, LucideAngularModule],
  templateUrl: './review.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ReviewComponent implements OnInit {
  private readonly reviewService = inject(ReviewService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly notificationService = inject(NotificationService);

  protected readonly reviews = signal<ApiReviewItem[]>([]);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);

  // Reject dialog
  protected readonly rejectTarget = signal<ApiReviewItem | null>(null);
  protected readonly rejectNotes = signal('');
  protected readonly isRejecting = signal(false);

  // Processing state
  protected readonly processingId = signal<string | null>(null);

  // Icons
  protected readonly ClipboardCheckIcon = ClipboardCheck;
  protected readonly CheckCircle2Icon = CheckCircle2;
  protected readonly XCircleIcon = XCircle;
  protected readonly Loader2Icon = Loader2;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly EyeIcon = Eye;
  protected readonly MessageSquareIcon = MessageSquare;
  protected readonly XIcon = X;

  ngOnInit(): void {
    this.loadReviews();
  }

  protected loadReviews(): void {
    this.isLoading.set(true);
    this.error.set(null);
    this.reviewService
      .getReviews()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.reviews.set(res.data);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('無法載入審核佇列');
          this.isLoading.set(false);
        },
      });
  }

  protected approveReview(review: ApiReviewItem): void {
    this.processingId.set(review.id);
    this.reviewService
      .approveReview(review.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.processingId.set(null);
          this.reviews.update((list) => list.filter((r) => r.id !== review.id));
          this.notificationService.success(`「${review.content_title}」已核准發布`);
        },
        error: () => {
          this.processingId.set(null);
          this.notificationService.error('核准失敗');
        },
      });
  }

  protected openRejectDialog(review: ApiReviewItem): void {
    this.rejectTarget.set(review);
    this.rejectNotes.set('');
  }

  protected closeRejectDialog(): void {
    this.rejectTarget.set(null);
  }

  protected onRejectNotesChange(event: Event): void {
    this.rejectNotes.set((event.target as HTMLTextAreaElement).value);
  }

  protected confirmReject(): void {
    const review = this.rejectTarget();
    if (!review) {
      return;
    }
    this.isRejecting.set(true);
    this.reviewService
      .rejectReview(review.id, this.rejectNotes())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isRejecting.set(false);
          this.closeRejectDialog();
          this.reviews.update((list) => list.filter((r) => r.id !== review.id));
          this.notificationService.success(`「${review.content_title}」已退回`);
        },
        error: () => {
          this.isRejecting.set(false);
          this.notificationService.error('退回失敗');
        },
      });
  }

  protected getReviewLevelConfig(level: ReviewLevel): { label: string; classes: string } {
    return REVIEW_LEVEL_CONFIG[level];
  }

  protected getContentTypeLabel(type: ContentType): string {
    return contentTypeLabelEn(type);
  }

}
