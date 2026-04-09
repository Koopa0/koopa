import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Check,
  X,
  FileText,
  Eye,
  Clock,
  Tag,
  Shield,
} from 'lucide-angular';
import { ContentService } from '../../core/services/content.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiContent } from '../../core/models/api.model';

@Component({
  selector: 'app-review',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './review.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ReviewComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly contentService = inject(ContentService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly content = signal<ApiContent | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly reviewerNotes = signal('');
  protected readonly isPublic = signal(true);
  protected readonly isSubmitting = signal(false);
  protected readonly isRejecting = signal(false);

  protected readonly contentId = computed(() => this.content()?.id ?? '');
  protected readonly typeBadgeColor = computed(() => {
    const type = this.content()?.type;
    switch (type) {
      case 'article':
        return 'bg-sky-500/20 text-sky-400';
      case 'essay':
        return 'bg-violet-500/20 text-violet-400';
      case 'build-log':
        return 'bg-amber-500/20 text-amber-400';
      case 'til':
        return 'bg-emerald-500/20 text-emerald-400';
      case 'note':
        return 'bg-zinc-500/20 text-zinc-400';
      case 'bookmark':
        return 'bg-orange-500/20 text-orange-400';
      case 'digest':
        return 'bg-rose-500/20 text-rose-400';
      default:
        return 'bg-zinc-500/20 text-zinc-400';
    }
  });

  protected readonly reviewLevelColor = computed(() => {
    const level = this.content()?.review_level;
    switch (level) {
      case 'auto':
        return 'text-emerald-400';
      case 'light':
        return 'text-sky-400';
      case 'standard':
        return 'text-amber-400';
      case 'strict':
        return 'text-red-400';
      default:
        return 'text-zinc-400';
    }
  });

  protected readonly topics = computed(
    () => this.content()?.topics?.map((t) => t.name) ?? [],
  );
  protected readonly tags = computed(() => this.content()?.tags ?? []);

  // Icons
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly CheckIcon = Check;
  protected readonly XIcon = X;
  protected readonly FileTextIcon = FileText;
  protected readonly EyeIcon = Eye;
  protected readonly ClockIcon = Clock;
  protected readonly TagIcon = Tag;
  protected readonly ShieldIcon = Shield;

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.loadContent(id);
    }
  }

  private loadContent(id: string): void {
    this.isLoading.set(true);
    this.contentService
      .adminGet(id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.content.set(data);
          this.isPublic.set(data.is_public);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load content');
        },
      });
  }

  protected updateNotes(event: Event): void {
    const target = event.target as HTMLTextAreaElement;
    this.reviewerNotes.set(target.value);
  }

  protected togglePublic(): void {
    this.isPublic.update((v) => !v);
  }

  protected approve(): void {
    const id = this.contentId();
    if (!id || this.isSubmitting()) return;

    this.isSubmitting.set(true);
    this.contentService
      .publish(id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.contentService
            .setVisibility(id, this.isPublic())
            .pipe(takeUntilDestroyed(this.destroyRef))
            .subscribe({
              next: () => {
                this.isSubmitting.set(false);
                this.notificationService.success(
                  'Content approved and published',
                );
                this.loadContent(id);
              },
              error: () => {
                this.isSubmitting.set(false);
                this.notificationService.error(
                  'Published but failed to set visibility',
                );
              },
            });
        },
        error: () => {
          this.isSubmitting.set(false);
          this.notificationService.error('Failed to publish content');
        },
      });
  }

  protected reject(): void {
    const id = this.contentId();
    const notes = this.reviewerNotes().trim();
    if (!id || this.isSubmitting()) return;
    if (!notes) {
      this.notificationService.error('Reviewer notes are required to reject');
      return;
    }

    this.isSubmitting.set(true);
    this.contentService
      .reject(id, notes)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isSubmitting.set(false);
          this.reviewerNotes.set('');
          this.isRejecting.set(false);
          this.notificationService.success(
            'Content rejected, returned to draft',
          );
          this.loadContent(id);
        },
        error: () => {
          this.isSubmitting.set(false);
          this.notificationService.error('Failed to reject content');
        },
      });
  }

  protected toggleRejectPanel(): void {
    this.isRejecting.update((v) => !v);
  }
}
