import {
  ChangeDetectionStrategy,
  Component,
  effect,
  inject,
} from '@angular/core';
import {
  NavigationEnd,
  Router,
  RouterLink,
  RouterLinkActive,
  RouterOutlet,
} from '@angular/router';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { A11yModule } from '@angular/cdk/a11y';
import { BreakpointObserver } from '@angular/cdk/layout';
import { filter, map } from 'rxjs/operators';
import { Accessibility, LogOut, LucideAngularModule } from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { KeyboardShortcutsService } from '../../core/services/keyboard-shortcuts.service';
import { AdminTopbarComponent } from './admin-topbar.component';
import { AdminTopbarService } from './admin-topbar.service';
import { ADMIN_NAV, type AdminNavItem } from './admin-nav.config';
import { AdminNavCountsService } from './admin-nav-counts.service';

/**
 * Admin shell — 6-group nav rail + Topbar + main router-outlet. Nav groups
 * follow the Mission Control design IA (Daily / Commitment / Knowledge /
 * Library / Input / System).
 * Counts are synthesized by
 * {@link AdminNavCountsService} until the unified
 * `/api/admin/system/health` envelope lands, and refreshed on every
 * navigation end so post-mutation pages see up-to-date counts.
 *
 * Height: `100dvh`. The admin area carries its own shell with no public
 * masthead above it (see app.html `isAdminArea` branch), so the rail fills
 * the full viewport.
 */
@Component({
  selector: 'app-admin-layout',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    LucideAngularModule,
    AdminTopbarComponent,
    A11yModule,
  ],
  templateUrl: './admin-layout.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex h-dvh flex-col',
    '(document:keydown.escape)': 'closeDrawer()',
  },
})
export class AdminLayoutComponent {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);
  private readonly keyboardShortcuts = inject(KeyboardShortcutsService);
  private readonly navCounts = inject(AdminNavCountsService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly breakpoints = inject(BreakpointObserver);

  protected readonly navGroups = ADMIN_NAV;
  protected readonly a11yMode = this.keyboardShortcuts.a11yMode;

  protected readonly drawerOpen = this.topbar.drawerOpen;
  protected readonly isMobile = toSignal(
    this.breakpoints.observe('(max-width: 767px)').pipe(map((s) => s.matches)),
    { initialValue: false },
  );

  /**
   * Resolve the live count for a nav item, or `null` when the item has
   * no wired count source yet (e.g. Today). Template gates the count
   * span on `!== null`.
   */
  protected countFor(item: AdminNavItem): number | null {
    if (!item.countKey) return null;
    return this.navCounts.counts()[item.countKey];
  }

  protected readonly LogOutIcon = LogOut;
  protected readonly AccessibilityIcon = Accessibility;

  constructor() {
    // Refresh nav counts after every successful navigation. A user
    // publishing content or replying to a task will almost always
    // navigate afterwards, so this catches post-mutation staleness
    // without coupling every mutation site to the nav service.
    this.router.events
      .pipe(
        filter((e): e is NavigationEnd => e instanceof NavigationEnd),
        takeUntilDestroyed(),
      )
      .subscribe(() => {
        this.navCounts.reload();
        this.topbar.closeDrawer();
      });

    // Close the drawer when the viewport grows to desktop so a left-open
    // mobile drawer doesn't strand focus in a now-static sidebar.
    effect(() => {
      if (!this.isMobile()) this.topbar.closeDrawer();
    });
  }

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }

  protected toggleA11yMode(): void {
    this.keyboardShortcuts.toggleA11yMode();
  }

  protected closeDrawer(): void {
    this.topbar.closeDrawer();
  }
}
