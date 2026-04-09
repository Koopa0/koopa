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
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  PenLine,
  FileText,
  Eye,
  Send,
  ChevronRight,
} from 'lucide-angular';
import { ContentService } from '../../core/services/content.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ContentPipeline } from '../../core/models/admin.model';

@Component({
  selector: 'app-pipeline',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './pipeline.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PipelineComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly pipeline = signal<ContentPipeline | null>(null);
  protected readonly isLoading = signal(true);

  protected readonly drafts = computed(
    () => this.pipeline()?.drafts_needing_work ?? [],
  );
  protected readonly inReview = computed(
    () => this.pipeline()?.in_review ?? [],
  );
  protected readonly readyToPublish = computed(
    () => this.pipeline()?.ready_to_publish ?? [],
  );
  protected readonly recentlyPublished = computed(
    () => this.pipeline()?.recently_published ?? [],
  );

  // Icons
  protected readonly PenLineIcon = PenLine;
  protected readonly FileTextIcon = FileText;
  protected readonly EyeIcon = Eye;
  protected readonly SendIcon = Send;
  protected readonly ChevronRightIcon = ChevronRight;

  protected readonly TYPE_COLORS: Record<string, string | undefined> = {
    article: 'bg-violet-900/40 text-violet-400',
    essay: 'bg-sky-900/40 text-sky-400',
    'build-log': 'bg-amber-900/40 text-amber-400',
    til: 'bg-emerald-900/40 text-emerald-400',
    note: 'bg-zinc-800/40 text-zinc-400',
    bookmark: 'bg-orange-900/40 text-orange-400',
    digest: 'bg-blue-900/40 text-blue-400',
  };

  ngOnInit(): void {
    this.loadPipeline();
  }

  private loadPipeline(): void {
    this.isLoading.set(true);
    this.contentService
      .getPipeline()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.pipeline.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load pipeline');
        },
      });
  }

  protected getTypeColor(type: string): string {
    return this.TYPE_COLORS[type] ?? 'bg-zinc-800/40 text-zinc-400';
  }

  protected getDaysAgo(dateStr: string): number {
    const date = new Date(dateStr);
    const now = new Date();
    return Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
  }
}
