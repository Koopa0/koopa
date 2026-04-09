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
  Send,
  FileText,
  Users,
  Clock,
  CircleDot,
  ArrowRight,
  Shield,
  Radio,
  Pencil,
  CheckCircle,
} from 'lucide-angular';
import { StudioService } from '../../core/services/studio.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  StudioOverview,
  ParticipantSummary,
  DirectiveLifecycle,
  DirectivePriority,
} from '../../core/models/admin.model';

@Component({
  selector: 'app-studio',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './studio.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StudioComponent implements OnInit {
  private readonly studioService = inject(StudioService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly overview = signal<StudioOverview | null>(null);
  protected readonly isLoading = signal(true);

  // Derived state
  protected readonly openDirectives = computed(
    () => this.overview()?.open_directives ?? [],
  );
  protected readonly unreadReports = computed(
    () => this.overview()?.unread_reports ?? [],
  );
  protected readonly participants = computed(
    () => this.overview()?.participants ?? [],
  );

  // Constant maps — full class strings, Tailwind JIT cannot parse dynamic concatenation
  protected readonly PRIORITY_CLASSES: Record<DirectivePriority, string> = {
    p0: 'bg-red-900/40 text-red-400',
    p1: 'bg-amber-900/40 text-amber-400',
    p2: 'bg-zinc-800 text-zinc-400',
  };

  protected readonly PRIORITY_LABELS: Record<DirectivePriority, string> = {
    p0: 'P0',
    p1: 'P1',
    p2: 'P2',
  };

  protected readonly LIFECYCLE_CLASSES: Record<DirectiveLifecycle, string> = {
    pending: 'bg-amber-900/40 text-amber-400',
    acknowledged: 'bg-sky-900/40 text-sky-400',
    resolved: 'bg-emerald-900/40 text-emerald-400',
  };

  protected readonly LIFECYCLE_LABELS: Record<DirectiveLifecycle, string> = {
    pending: 'Pending',
    acknowledged: 'Acknowledged',
    resolved: 'Resolved',
  };

  // Lucide icons
  protected readonly SendIcon = Send;
  protected readonly FileTextIcon = FileText;
  protected readonly UsersIcon = Users;
  protected readonly ClockIcon = Clock;
  protected readonly CircleDotIcon = CircleDot;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly ShieldIcon = Shield;
  protected readonly RadioIcon = Radio;
  protected readonly PencilIcon = Pencil;
  protected readonly CheckCircleIcon = CheckCircle;

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
          this.notificationService.error('Failed to load Studio overview');
        },
      });
  }

  protected truncateContent(content: string, maxLength: number): string {
    if (content.length <= maxLength) return content;
    return content.slice(0, maxLength) + '...';
  }

  protected getCapabilityLabel(key: string): string {
    const labels: Record<string, string> = {
      can_issue_directives: 'Issue Directives',
      can_receive_directives: 'Receive Directives',
      can_write_reports: 'Write Reports',
      task_assignable: 'Task Assignable',
    };
    return labels[key] ?? key;
  }

  protected getCapabilities(
    participant: ParticipantSummary,
  ): { key: string; label: string; active: boolean }[] {
    return [
      {
        key: 'can_issue_directives',
        label: 'Issue Directives',
        active: participant.can_issue_directives,
      },
      {
        key: 'can_receive_directives',
        label: 'Receive Directives',
        active: participant.can_receive_directives,
      },
      {
        key: 'can_write_reports',
        label: 'Write Reports',
        active: participant.can_write_reports,
      },
      {
        key: 'task_assignable',
        label: 'Assignable',
        active: participant.task_assignable,
      },
    ];
  }
}
