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
  Brain,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  ChevronRight,
  Clock,
} from 'lucide-angular';
import {
  LearnService,
  type ConceptDrilldown,
  type ConceptObservation,
} from '../../core/services/learn.service';
import { NotificationService } from '../../core/services/notification.service';

@Component({
  selector: 'app-concept-drilldown',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './concept-drilldown.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ConceptDrilldownComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly learnService = inject(LearnService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly concept = signal<ConceptDrilldown | null>(null);
  protected readonly isLoading = signal(true);

  // Derived
  protected readonly conceptName = computed(
    () => this.concept()?.name ?? 'Loading...',
  );
  protected readonly observations = computed(
    () => this.concept()?.observations ?? [],
  );
  protected readonly recentAttempts = computed(
    () => this.concept()?.recent_attempts ?? [],
  );
  protected readonly relatedConcepts = computed(
    () => this.concept()?.related_concepts ?? [],
  );
  protected readonly successRate = computed(
    () => this.concept()?.success_rate ?? 0,
  );
  protected readonly totalAttempts = computed(
    () => this.concept()?.total_attempts ?? 0,
  );

  protected readonly masteryLevel = computed(() => {
    const rate = this.successRate();
    if (rate >= 80)
      return {
        label: 'Proficient',
        color: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
      };
    if (rate >= 50)
      return {
        label: 'Developing',
        color: 'text-amber-400 bg-amber-950/30 border-amber-800/30',
      };
    if (rate > 0)
      return {
        label: 'Weak',
        color: 'text-red-400 bg-red-950/30 border-red-800/30',
      };
    return {
      label: 'Untested',
      color: 'text-zinc-400 bg-zinc-800/30 border-zinc-700/30',
    };
  });

  // Icons
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly BrainIcon = Brain;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly TrendingUpIcon = TrendingUp;
  protected readonly TrendingDownIcon = TrendingDown;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly ClockIcon = Clock;

  protected readonly OUTCOME_COLORS: Record<string, string | undefined> = {
    solved_independent: 'text-emerald-400',
    solved_with_hint: 'text-amber-400',
    solved_after_solution: 'text-orange-400',
    completed: 'text-emerald-400',
    completed_with_support: 'text-amber-400',
    incomplete: 'text-red-400',
    gave_up: 'text-red-500',
  };

  protected readonly OUTCOME_LABELS: Record<string, string | undefined> = {
    solved_independent: 'Solved',
    solved_with_hint: 'With hint',
    solved_after_solution: 'After solution',
    completed: 'Completed',
    completed_with_support: 'With support',
    incomplete: 'Incomplete',
    gave_up: 'Gave up',
  };

  protected readonly SIGNAL_COLORS: Record<string, string | undefined> = {
    weakness: 'text-red-400',
    improvement: 'text-amber-400',
    mastery: 'text-emerald-400',
  };

  protected readonly RELATION_LABELS: Record<string, string | undefined> = {
    prerequisite: 'Prerequisite',
    easier_variant: 'Easier variant',
    harder_variant: 'Harder variant',
    same_pattern: 'Same pattern',
    follow_up: 'Follow-up',
    similar_structure: 'Similar',
  };

  ngOnInit(): void {
    const slug = this.route.snapshot.paramMap.get('slug');
    if (slug) {
      this.loadConcept(slug);
    }
  }

  private loadConcept(slug: string): void {
    this.isLoading.set(true);
    this.learnService
      .getConceptDrilldown(slug)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.concept.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load concept data');
        },
      });
  }

  protected getObservationSignalIcon(
    obs: ConceptObservation,
  ): typeof TrendingUp | typeof TrendingDown | typeof AlertTriangle {
    if (obs.signal === 'mastery') return this.TrendingUpIcon;
    if (obs.signal === 'improvement') return this.TrendingUpIcon;
    return this.AlertTriangleIcon;
  }

  protected formatMinutes(seconds: number): number {
    return Math.round(seconds / 60);
  }
}
