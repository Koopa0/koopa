import { Injectable, inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { Router } from '@angular/router';
import { fromEvent, Subscription } from 'rxjs';
import { filter } from 'rxjs/operators';

@Injectable({
  providedIn: 'root',
})
export class KeyboardShortcutsService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly router = inject(Router);
  private subscription: Subscription | null = null;

  init(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    // 避免重複訂閱
    this.subscription?.unsubscribe();

    this.subscription = fromEvent<KeyboardEvent>(document, 'keydown')
      .pipe(
        filter((event) => {
          const target = event.target as HTMLElement;
          return !['INPUT', 'TEXTAREA'].includes(target.tagName);
        }),
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

  destroy(): void {
    this.subscription?.unsubscribe();
    this.subscription = null;
  }
}
