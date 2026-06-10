import {
  Injectable,
  signal,
  computed,
  PLATFORM_ID,
  inject,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

export type Theme = 'dark' | 'light';

const THEME_STORAGE_KEY = 'koopa-theme';

/** Browser theme-color values approximating the DS --bg surface per theme. */
const THEME_COLOR: Record<Theme, string> = {
  dark: '#141417',
  light: '#fbfaf8',
};

/**
 * ThemeService — dark (default) / light theme switching.
 *
 * The choice is persisted to localStorage and applied as `data-theme` on
 * `<html>`, which drives the DS token swap in styles.css. An inline script
 * in index.html applies the persisted choice before first paint so SSR
 * hydration never flashes the wrong theme; this service takes over from
 * there for runtime toggling.
 */
@Injectable({
  providedIn: 'root',
})
export class ThemeService {
  private readonly platformId = inject(PLATFORM_ID);

  private readonly _theme = signal<Theme>(this.readInitialTheme());
  readonly theme = this._theme.asReadonly();
  readonly isDarkMode = computed(() => this._theme() === 'dark');

  constructor() {
    if (isPlatformBrowser(this.platformId)) {
      this.applyTheme(this._theme());
    }
  }

  toggleTheme(): void {
    this.setTheme(this._theme() === 'dark' ? 'light' : 'dark');
  }

  setTheme(theme: Theme): void {
    this._theme.set(theme);

    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Private browsing may block storage — the in-memory theme still applies.
    }
    this.applyTheme(theme);
  }

  private readInitialTheme(): Theme {
    if (!isPlatformBrowser(this.platformId)) {
      return 'dark';
    }
    try {
      return localStorage.getItem(THEME_STORAGE_KEY) === 'light'
        ? 'light'
        : 'dark';
    } catch {
      return 'dark';
    }
  }

  private applyTheme(theme: Theme): void {
    document.documentElement.setAttribute('data-theme', theme);

    const color = THEME_COLOR[theme];
    const themeColorMeta = document.querySelector('meta[name="theme-color"]');

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
