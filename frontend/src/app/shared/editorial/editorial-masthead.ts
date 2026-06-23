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
import { toSignal } from '@angular/core/rxjs-interop';
import { filter, map } from 'rxjs';
import {
  LucideAngularModule,
  Github,
  LayoutDashboard,
  LogOut,
} from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { CommandPaletteService } from '../command-palette/command-palette.service';
import { ThemeToggleComponent } from '../theme-toggle/theme-toggle';

/**
 * The public masthead — the Tone B letterhead. Serif wordmark over a mono
 * "written & maintained by one person" subline (the serif=human /
 * mono=machine signature), a Writing nav link, a ⌘K search button wired
 * to the command palette, and the theme toggle. Admin / sign-out controls
 * surface only for the authenticated owner.
 */
@Component({
  selector: 'app-editorial-masthead',
  imports: [RouterLink, LucideAngularModule, ThemeToggleComponent],
  templateUrl: './editorial-masthead.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EditorialMastheadComponent {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);
  protected readonly commandPalette = inject(CommandPaletteService);

  protected readonly isAuthenticated = this.authService.isAuthenticated;

  protected readonly GithubIcon = Github;
  protected readonly DashboardIcon = LayoutDashboard;
  protected readonly LogOutIcon = LogOut;

  private readonly currentPath = computed(() => this.currentUrl().split('?')[0]);

  /** Writing covers the reading index, topics, and the article surface. */
  protected readonly writingActive = computed(() => {
    const path = this.currentPath();
    return (
      path === '/' ||
      path.startsWith('/articles') ||
      path.startsWith('/topics')
    );
  });

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
