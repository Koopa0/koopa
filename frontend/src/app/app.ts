import {
  Component,
  ChangeDetectionStrategy,
  computed,
  inject,
  PLATFORM_ID,
  afterNextRender,
} from '@angular/core';
import {
  Router,
  RouterOutlet,
  RouterLink,
  NavigationEnd,
} from '@angular/router';
import { isPlatformBrowser } from '@angular/common';
import { filter, map } from 'rxjs/operators';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  LogOut,
  LayoutDashboard,
  Search,
  Github,
} from 'lucide-angular';
import { BackToTopComponent } from './shared/back-to-top/back-to-top.component';
import { CommandPaletteComponent } from './shared/command-palette/command-palette.component';
import { ToastComponent } from './shared/toast/toast.component';
import { ThemeToggleComponent } from './shared/theme-toggle/theme-toggle';
import { CommandPaletteService } from './shared/command-palette/command-palette.service';
import { AuthService } from './core/services/auth.service';
import { KeyboardShortcutsService } from './core/services/keyboard-shortcuts.service';

@Component({
  selector: 'app-root',
  imports: [
    RouterOutlet,
    RouterLink,
    LucideAngularModule,
    BackToTopComponent,
    CommandPaletteComponent,
    ToastComponent,
    ThemeToggleComponent,
  ],
  templateUrl: './app.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-dvh flex-col',
  },
})
export class AppComponent {
  protected readonly title = 'koopa.dev';

  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly keyboardShortcuts = inject(KeyboardShortcutsService);
  protected readonly commandPalette = inject(CommandPaletteService);

  protected readonly isAuthenticated = this.authService.isAuthenticated;
  protected readonly currentYear = new Date().getFullYear();

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

  /** Preview routes render the bare reading column for the admin iframe. */
  protected readonly isChromeless = computed(() =>
    this.currentPath().startsWith('/preview'),
  );

  protected readonly articlesActive = computed(() => {
    const path = this.currentPath();
    return (
      path === '/' ||
      path.startsWith('/articles') ||
      path.startsWith('/topics') ||
      path.startsWith('/essays') ||
      path.startsWith('/til') ||
      path.startsWith('/build-logs')
    );
  });

  protected readonly projectsActive = computed(() =>
    this.currentPath().startsWith('/projects'),
  );

  // Lucide icons
  protected readonly LogOutIcon = LogOut;
  protected readonly DashboardIcon = LayoutDashboard;
  protected readonly SearchIcon = Search;
  protected readonly GithubIcon = Github;

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

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }
}
