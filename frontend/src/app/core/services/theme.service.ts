import { Injectable, signal, PLATFORM_ID, inject } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

/**
 * ThemeService — currently only supports dark mode.
 * Retained for future extensibility, but no toggle functionality is provided.
 */
@Injectable({
  providedIn: 'root',
})
export class ThemeService {
  private readonly platformId = inject(PLATFORM_ID);

  readonly isDarkMode = signal(true);

  constructor() {
    if (isPlatformBrowser(this.platformId)) {
      this.ensureDarkTheme();
    }
  }

  private ensureDarkTheme(): void {
    document.documentElement.setAttribute('data-theme', 'dark');

    const themeColorMeta = document.querySelector('meta[name="theme-color"]');
    const color = '#09090b';

    if (themeColorMeta) {
      themeColorMeta.setAttribute('content', color);
    } else {
      const meta = document.createElement('meta');
      meta.name = 'theme-color';
      meta.content = color;
      document.head.appendChild(meta);
    }
  }
}
