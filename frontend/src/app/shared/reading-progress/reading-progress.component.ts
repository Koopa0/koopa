import {
  Component,
  ChangeDetectionStrategy,
  signal,
  inject,
  DestroyRef,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { fromEvent, throttleTime } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Component({
  selector: 'app-reading-progress',
  standalone: true,
  template: `
    <div class="fixed top-16 right-0 left-0 z-50 h-0.5 bg-zinc-800">
      <div
        class="h-full bg-white transition-[width] duration-150"
        [style.width.%]="progress()"
      ></div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ReadingProgressComponent {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly progress = signal(0);

  constructor() {
    if (isPlatformBrowser(this.platformId)) {
      fromEvent(window, 'scroll')
        .pipe(throttleTime(50), takeUntilDestroyed(this.destroyRef))
        .subscribe(() => {
          const scrollTop = window.scrollY;
          const docHeight =
            document.documentElement.scrollHeight - window.innerHeight;
          const scrollProgress =
            docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
          this.progress.set(Math.min(100, Math.max(0, scrollProgress)));
        });
    }
  }
}
