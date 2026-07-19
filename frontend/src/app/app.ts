import {
  Component,
  ChangeDetectionStrategy,
  computed,
  effect,
  inject,
  PLATFORM_ID,
  afterNextRender,
} from '@angular/core';
import { Router, RouterOutlet, NavigationEnd } from '@angular/router';
import { isPlatformBrowser } from '@angular/common';
import { filter, map } from 'rxjs/operators';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { BackToTopComponent } from './shared/back-to-top/back-to-top.component';
import { CommandPaletteComponent } from './shared/command-palette/command-palette.component';
import { ToastComponent } from './shared/toast/toast.component';
import { EditorialMastheadComponent } from './shared/editorial/editorial-masthead';
import { EditorialFooterComponent } from './shared/editorial/editorial-footer';
import { KeyboardShortcutsService } from './core/services/keyboard-shortcuts.service';
import { ThemeService } from './core/services/theme.service';

/**
 * The application shell — picks the chrome for the current route. The public
 * reading site wears the editorial Tone B frame (masthead + footer); the
 * admin area carries its own shell; login is a standalone full-screen page.
 */
@Component({
  selector: 'app-root',
  imports: [
    RouterOutlet,
    BackToTopComponent,
    CommandPaletteComponent,
    ToastComponent,
    EditorialMastheadComponent,
    EditorialFooterComponent,
  ],
  templateUrl: './app.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-dvh flex-col',
  },
})
export class AppComponent {
  private readonly router = inject(Router);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly keyboardShortcuts = inject(KeyboardShortcutsService);
  private readonly themeService = inject(ThemeService);

  private readonly currentUrl = toSignal(
    this.router.events.pipe(
      filter((event): event is NavigationEnd => event instanceof NavigationEnd),
      map((event) => event.urlAfterRedirects),
    ),
    { initialValue: this.router.url },
  );

  private readonly currentPath = computed(
    () => this.currentUrl().split('?')[0],
  );

  /**
   * Routes that render bare — no editorial masthead or footer.
   */
  protected readonly isChromeless = computed(
    () => this.currentPath() === '/login',
  );

  /** The admin area carries its own shell (sidebar + topbar). */
  protected readonly isAdminArea = computed(() =>
    this.currentPath().startsWith('/admin'),
  );

  /**
   * Public reading site: everything that is neither login nor the admin area.
   * This is the surface that wears the editorial frame.
   */
  protected readonly isPublicSite = computed(
    () => !this.isChromeless() && !this.isAdminArea(),
  );

  constructor() {
    // Keep the ROOT color-scheme + background in sync with the public surface so
    // the viewport scrollbar and overscroll gutter match the page (the .ed paper
    // tokens don't reach the root). Admin keeps the global oklch-dark root.
    effect(() => {
      if (!isPlatformBrowser(this.platformId)) {
        return;
      }
      const root = document.documentElement;
      if (this.isPublicSite()) {
        const dark = this.themeService.isDarkMode();
        root.style.colorScheme = dark ? 'dark' : 'light';
        root.style.background = dark ? '#14130f' : '#edeae2';
      } else {
        // Hand the root back to the admin/global dark tokens.
        root.style.removeProperty('color-scheme');
        root.style.removeProperty('background');
      }
    });

    afterNextRender(() => {
      this.keyboardShortcuts.init();
    });

    this.router.events
      .pipe(
        filter(
          (event): event is NavigationEnd => event instanceof NavigationEnd,
        ),
        takeUntilDestroyed(),
      )
      .subscribe(() => {
        if (isPlatformBrowser(this.platformId)) {
          window.scrollTo(0, 0);
        }
      });
  }
}
