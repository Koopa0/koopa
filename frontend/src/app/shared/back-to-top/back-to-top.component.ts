import {
  Component,
  signal,
  inject,
  PLATFORM_ID,
  ChangeDetectionStrategy,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { fromEvent, throttleTime } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LucideAngularModule, ChevronUp } from 'lucide-angular';

@Component({
  selector: 'app-back-to-top',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    <button
      type="button"
      class="fixed bottom-6 right-6 z-50 rounded-full bg-zinc-800 p-3 text-zinc-300 shadow-lg transition-all hover:-translate-y-1 hover:bg-zinc-700 hover:text-white sm:bottom-8 sm:right-8"
      [class.opacity-0]="!isVisible()"
      [class.pointer-events-none]="!isVisible()"
      [class.opacity-100]="isVisible()"
      [class.translate-y-0]="isVisible()"
      (click)="scrollToTop()"
      aria-label="Back to top"
    >
      <lucide-icon [img]="ChevronUpIcon" [size]="20" />
    </button>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BackToTopComponent {
  private readonly platformId = inject(PLATFORM_ID);

  protected readonly isVisible = signal(false);
  protected readonly ChevronUpIcon = ChevronUp;

  constructor() {
    if (isPlatformBrowser(this.platformId)) {
      fromEvent(window, 'scroll')
        .pipe(throttleTime(100), takeUntilDestroyed())
        .subscribe(() => {
          this.isVisible.set(window.scrollY > 300);
        });
    }
  }

  protected scrollToTop(): void {
    if (isPlatformBrowser(this.platformId)) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }
}
