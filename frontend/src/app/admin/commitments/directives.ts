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
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Users,
  Send,
  FileText,
  ArrowRight,
  Clock,
  CheckCircle,
} from 'lucide-angular';
import { StudioService } from '../../core/services/studio.service';
import { NotificationService } from '../../core/services/notification.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { ModalComponent } from '../../shared/components/modal/modal.component';
import type {
  StudioOverview,
  DirectiveSummary,
  ReportSummary,
  ParticipantSummary,
} from '../../core/models/admin.model';

interface DirectivesByTarget {
  participant: string;
  directives: DirectiveSummary[];
}

@Component({
  selector: 'app-directives',
  standalone: true,
  imports: [DatePipe, LucideAngularModule, ModalComponent],
  templateUrl: './directives.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DirectivesComponent implements OnInit {
  private readonly studioService = inject(StudioService);
  private readonly notificationService = inject(NotificationService);
  private readonly markdownService = inject(MarkdownService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly overview = signal<StudioOverview | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly selectedDirective = signal<DirectiveSummary | null>(null);
  protected readonly selectedReport = signal<ReportSummary | null>(null);

  protected readonly directives = computed(
    () => this.overview()?.open_directives ?? [],
  );
  protected readonly reports = computed(
    () => this.overview()?.recent_reports ?? [],
  );
  protected readonly participants = computed(
    () => this.overview()?.participants ?? [],
  );

  protected readonly directivesByTarget = computed<DirectivesByTarget[]>(() => {
    const map = new Map<string, DirectiveSummary[]>();
    for (const d of this.directives()) {
      const existing = map.get(d.target);
      if (existing) {
        existing.push(d);
      } else {
        map.set(d.target, [d]);
      }
    }
    return Array.from(map.entries()).map(([participant, directives]) => ({
      participant,
      directives,
    }));
  });

  /**
   * Parsed-HTML caches, keyed by report/directive id.
   *
   * SECURITY_REVIEW: content is parsed through MarkdownService which runs
   * DOMPurify with an allow-list in the browser. The source is our own
   * admin backend (trusted). Same pattern as pages/essay-detail,
   * pages/article-detail, etc.
   *
   * Caching via computed() avoids re-parsing on every change detection
   * cycle — parsing + highlight.js can be expensive for long reports.
   */
  protected readonly reportHtmlCache = computed<Map<number, string>>(() => {
    const cache = new Map<number, string>();
    for (const r of this.reports()) {
      cache.set(r.id, this.markdownService.parse(r.content ?? ''));
    }
    return cache;
  });

  protected readonly directiveHtmlCache = computed<Map<number, string>>(() => {
    const cache = new Map<number, string>();
    for (const d of this.directives()) {
      cache.set(d.id, this.markdownService.parse(d.content ?? ''));
    }
    return cache;
  });

  protected readonly hasOpenDirectives = computed(
    () => this.directives().length > 0,
  );

  // Icons
  protected readonly UsersIcon = Users;
  protected readonly SendIcon = Send;
  protected readonly FileTextIcon = FileText;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly ClockIcon = Clock;
  protected readonly CheckCircleIcon = CheckCircle;

  protected readonly LIFECYCLE_COLORS: Record<string, string | undefined> = {
    pending: 'text-amber-400 bg-amber-950/30 border-amber-800/30',
    acknowledged: 'text-sky-400 bg-sky-950/30 border-sky-800/30',
    resolved: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
  };

  protected readonly PRIORITY_COLORS: Record<string, string | undefined> = {
    p0: 'text-red-400',
    p1: 'text-amber-400',
    p2: 'text-zinc-500',
  };

  ngOnInit(): void {
    this.loadOverview();
  }

  private loadOverview(): void {
    this.isLoading.set(true);
    this.studioService
      .getOverview()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.overview.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load directives');
        },
      });
  }

  protected getLifecycleColor(status: string): string {
    return (
      this.LIFECYCLE_COLORS[status] ??
      'text-zinc-400 bg-zinc-800/50 border-zinc-700'
    );
  }

  protected getPriorityColor(priority: string): string {
    return this.PRIORITY_COLORS[priority] ?? 'text-zinc-500';
  }

  protected getAgeColor(days: number): string {
    if (days > 7) return 'text-red-400';
    if (days > 3) return 'text-amber-400';
    return 'text-zinc-500';
  }

  protected renderReport(id: number): string {
    return this.reportHtmlCache().get(id) ?? '';
  }

  protected renderDirective(id: number): string {
    return this.directiveHtmlCache().get(id) ?? '';
  }

  protected canIssue(p: ParticipantSummary): boolean {
    return p.can_issue_directives;
  }

  protected canReceive(p: ParticipantSummary): boolean {
    return p.can_receive_directives;
  }

  protected selectDirective(directive: DirectiveSummary): void {
    this.selectedDirective.set(directive);
  }

  protected closeDetail(): void {
    this.selectedDirective.set(null);
  }

  protected selectReport(report: ReportSummary): void {
    this.selectedReport.set(report);
  }

  protected closeReportDetail(): void {
    this.selectedReport.set(null);
  }

  protected getRelatedReports(directiveId: number): ReportSummary[] {
    return this.reports().filter((r) => r.in_response_to === directiveId);
  }
}
