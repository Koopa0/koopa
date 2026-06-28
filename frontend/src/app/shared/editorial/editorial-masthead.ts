import {
  Component,
  ChangeDetectionStrategy,
  computed,
  inject,
} from '@angular/core';
import {
  Router,
  RouterLink,
  NavigationEnd,
} from '@angular/router';
import { NgOptimizedImage } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { filter, map } from 'rxjs';
import { LucideAngularModule, LayoutDashboard, LogOut } from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { ThemeToggleComponent } from '../theme-toggle/theme-toggle';

/**
 * The public masthead — the serif wordmark beside the koopa mark, a segmented
 * mono pill nav across the site's two organizing axes (the work = by time,
 * topics = by theme) plus about, and the theme toggle. Admin / sign-out
 * controls surface only for the authenticated owner.
 */
@Component({
  selector: 'app-editorial-masthead',
  imports: [RouterLink, NgOptimizedImage, LucideAngularModule, ThemeToggleComponent],
  templateUrl: './editorial-masthead.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EditorialMastheadComponent {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);

  protected readonly isAuthenticated = this.authService.isAuthenticated;

  protected readonly DashboardIcon = LayoutDashboard;
  protected readonly LogOutIcon = LogOut;

  private readonly currentPath = computed(() => this.currentUrl().split('?')[0]);

  /** "articles" — the chronological axis: the front door and every piece. */
  protected readonly articlesActive = computed(() => {
    const path = this.currentPath();
    return path === '/' || path.startsWith('/articles');
  });

  /** "topics" — the thematic axis: the index and per-topic pages. */
  protected readonly topicsActive = computed(() =>
    this.currentPath().startsWith('/topics'),
  );

  protected readonly aboutActive = computed(() =>
    this.currentPath().startsWith('/about'),
  );

  private readonly currentUrl = toSignal(
    this.router.events.pipe(
      filter((event): event is NavigationEnd => event instanceof NavigationEnd),
      map((event) => event.urlAfterRedirects),
    ),
    { initialValue: this.router.url },
  );

  protected logout(): void {
    this.authService.logout();
    void this.router.navigate(['/']);
  }
}
