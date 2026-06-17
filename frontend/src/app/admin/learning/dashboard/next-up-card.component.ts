import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { LearningService } from '../../../core/services/learning.service';
import { NotificationService } from '../../../core/services/notification.service';
import type { NextTarget } from '../../../core/models/learning.model';

// A weakness-led recommendation drills the weak concept, so the session it
// starts opens in review mode. Koopa can pick another mode from the full
// sessions surface; the card optimizes the one-click "practice this now" path.
const RECOMMENDED_MODE = 'review' as const;

/**
 * Next-up card. Reads the single weakest concept to practice next and turns
 * the see-what-to-practice → practice-it-now loop into one action: Start
 * session opens a review session in the recommended concept's domain. The
 * read is independent so the card never blanks the rest of the dashboard,
 * and the start handles the one-active-session-at-a-time rule by surfacing
 * the conflict rather than failing silently.
 */
@Component({
  selector: 'app-next-up-card',
  standalone: true,
  templateUrl: './next-up-card.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NextUpCardComponent {
  private readonly learningService = inject(LearningService);
  private readonly notifications = inject(NotificationService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly starting = signal(false);

  protected readonly resource = rxResource<NextTarget, void>({
    stream: () => this.learningService.nextTarget(),
  });

  protected readonly target = computed<NextTarget | undefined>(() =>
    this.resource.hasValue() ? this.resource.value() : undefined,
  );
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly hasTarget = computed(() => {
    const t = this.target();
    return !!t && !t.empty;
  });

  protected reload(): void {
    this.resource.reload();
  }

  protected startSession(): void {
    const t = this.target();
    if (!t || t.empty || !t.domain || this.starting()) return;
    this.starting.set(true);
    this.learningService
      .startSession(t.domain, RECOMMENDED_MODE)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (session) => {
          void this.router.navigate([
            '/admin/learning/sessions',
            session.id,
          ]);
        },
        error: () => {
          this.starting.set(false);
          this.notifications.error(
            'A session may already be active — open Sessions to continue it.',
          );
        },
      });
  }
}
