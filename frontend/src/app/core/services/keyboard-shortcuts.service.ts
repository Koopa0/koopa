import { DestroyRef, Injectable, inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { fromEvent } from 'rxjs';
import { filter } from 'rxjs/operators';

@Injectable({
  providedIn: 'root',
})
export class KeyboardShortcutsService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);
  private isInitialized = false;

  init(): void {
    if (!isPlatformBrowser(this.platformId) || this.isInitialized) {
      return;
    }

    this.isInitialized = true;

    fromEvent<KeyboardEvent>(document, 'keydown')
      .pipe(
        filter((event) => {
          const target = event.target as HTMLElement;
          return !['INPUT', 'TEXTAREA'].includes(target.tagName);
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe((event) => {
        if (event.key === 'g' && event.shiftKey) {
          window.scrollTo({
            top: document.body.scrollHeight,
            behavior: 'smooth',
          });
        }

        if (event.key === 'j') {
          window.scrollBy({ top: 100, behavior: 'smooth' });
        } else if (event.key === 'k' && !event.metaKey && !event.ctrlKey) {
          window.scrollBy({ top: -100, behavior: 'smooth' });
        }
      });
  }
}
