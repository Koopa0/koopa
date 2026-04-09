import {
  Component,
  ChangeDetectionStrategy,
  inject,
  input,
  signal,
  computed,
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
import type { ApiReviewItem, ReviewLevel } from '../../core/models';
import { contentTypeLabelEn } from '../../core/models';

const REVIEW_LEVEL_CONFIG: Record<
  ReviewLevel,
  { label: string; classes: string }
> = {
  auto: { label: 'Auto', classes: 'border-zinc-600 bg-zinc-800 text-zinc-300' },
  light: {
    label: 'Light',
    classes: 'border-sky-700 bg-sky-900/30 text-sky-400',
  },
  standard: {
    label: 'Standard',
    classes: 'border-amber-700 bg-amber-900/30 text-amber-400',
  },
  strict: {
    label: 'Strict',
    classes: 'border-red-700 bg-red-900/30 text-red-400',
  },
};

@Component({
  selector: 'app-review',
  standalone: true,
  imports: [DatePipe, RouterLink, LucideAngularModule],
  templateUrl: './review.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ReviewComponent implements OnInit {
  readonly hideHeader = input(false);

  private readonly reviewService = inject(ReviewService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly notificationService = inject(NotificationService);

  protected readonly reviews = signal<ApiReviewItem[]>([]);
  protected readonly displayReviews = computed(() =>
    this.reviews().map((r) => ({
      ...r,
      levelConfig: REVIEW_LEVEL_CONFIG[r.review_level],
      typeLabel: contentTypeLabelEn(r.content_type),
    })),
  );
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
          this.error.set('Failed to load review queue');
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
          this.notificationService.success(
            `"${review.content_title}" approved for publication`,
          );
        },
        error: () => {
          this.processingId.set(null);
          this.notificationService.error('Approval failed');
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
          this.notificationService.success(
            `"${review.content_title}" rejected`,
          );
        },
        error: () => {
          this.isRejecting.set(false);
          this.notificationService.error('Rejection failed');
        },
      });
  }
}
