import {
  Component,
  ChangeDetectionStrategy,
  computed,
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

/**
 * The application shell — picks the chrome for the current route. The public
 * reading site wears the editorial Tone B frame (masthead + footer); the
 * admin area carries its own shell; the publish-preview iframe is bare.
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
   * Routes that render bare — no editorial masthead or footer: the admin
   * preview iframe column, and the standalone full-screen login.
   */
  protected readonly isChromeless = computed(
    () =>
      this.currentPath().startsWith('/preview') ||
      this.currentPath() === '/login',
  );

  /** The admin area carries its own shell (sidebar + topbar). */
  protected readonly isAdminArea = computed(() =>
    this.currentPath().startsWith('/admin'),
  );

  /**
   * Public reading site: everything that is neither the chrome-less preview
   * nor the admin area. This is the surface that wears the editorial frame.
   */
  protected readonly isPublicSite = computed(
    () => !this.isChromeless() && !this.isAdminArea(),
  );

  constructor() {
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
