import {
  Injectable,
  signal,
  computed,
  PLATFORM_ID,
  inject,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

/** Public surface theme: 'light' is the warm-paper default, 'dark' its twin. */
export type Theme = 'dark' | 'light';

const THEME_STORAGE_KEY = 'koopa-public-theme';

/** Browser theme-color values approximating the public --bg surface per theme. */
const THEME_COLOR: Record<Theme, string> = {
  dark: '#14130f',
  light: '#edeae2',
};

/**
 * ThemeService — the PUBLIC site's warm-paper (default) / dark twin switch.
 *
 * The public palette is scoped to `.ed` / `.ed-theme` (see editorial.css), so
 * the admin surface keeps its own global oklch-dark tokens and is never touched
 * by this toggle. The dark twin is applied as the `public-dark` class on
 * `<html>`; an inline script in index.html applies the persisted choice before
 * first paint (admin paths are forced dark there too) so SSR hydration never
 * flashes the wrong theme. This service takes over for runtime toggling.
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
      return 'light';
    }
    try {
      return localStorage.getItem(THEME_STORAGE_KEY) === 'dark'
        ? 'dark'
        : 'light';
    } catch {
      return 'light';
    }
  }

  private applyTheme(theme: Theme): void {
    document.documentElement.classList.toggle('public-dark', theme === 'dark');

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
