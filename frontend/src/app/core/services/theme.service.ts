import { Injectable, signal, PLATFORM_ID, inject } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

/**
 * ThemeService — 目前僅支援深色模式。
 * 保留此 service 以便未來擴展，但不再提供切換功能。
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
