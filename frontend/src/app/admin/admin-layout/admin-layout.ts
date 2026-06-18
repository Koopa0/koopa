import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import {
  NavigationEnd,
  Router,
  RouterLink,
  RouterLinkActive,
  RouterOutlet,
} from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { filter } from 'rxjs/operators';
import { Accessibility, LogOut, LucideAngularModule } from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { KeyboardShortcutsService } from '../../core/services/keyboard-shortcuts.service';
import { ToastComponent } from '../../shared/toast/toast.component';
import { AdminTopbarComponent } from './admin-topbar.component';
import { ADMIN_NAV, type AdminNavItem } from './admin-nav.config';
import { AdminNavCountsService } from './admin-nav-counts.service';

/**
 * Admin shell — 5-domain nav rail + Topbar + main router-outlet.
 * Replaces the legacy NOW/ATLAS 2-mode shell. Nav groups follow the
 * Mission Control design IA (Daily / Commitment / Knowledge / Learning
 * / System). Counts are synthesized by
 * {@link AdminNavCountsService} until the unified
 * `/api/admin/system/health` envelope lands, and refreshed on every
 * navigation end so post-mutation pages see up-to-date counts.
 *
 * Height: `100dvh - 57px` matches the public AppShell navbar. The magic
 * number is intentional until that shell exports a CSS custom property.
 */
@Component({
  selector: 'app-admin-layout',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    LucideAngularModule,
    ToastComponent,
    AdminTopbarComponent,
  ],
  templateUrl: './admin-layout.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex h-[calc(100dvh-57px)] flex-col' },
})
export class AdminLayoutComponent {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);
  private readonly keyboardShortcuts = inject(KeyboardShortcutsService);
  private readonly navCounts = inject(AdminNavCountsService);

  protected readonly navGroups = ADMIN_NAV;
  protected readonly a11yMode = this.keyboardShortcuts.a11yMode;

  /**
   * Resolve the live count for a nav item, or `null` when the item has
   * no wired count source yet (e.g. Today, Learning dashboard). Template
   * gates the count span on `!== null`.
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
      .subscribe(() => this.navCounts.reload());
  }

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }

  protected toggleA11yMode(): void {
    this.keyboardShortcuts.toggleA11yMode();
  }
}
