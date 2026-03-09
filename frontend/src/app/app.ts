import {
  Component,
  ChangeDetectionStrategy,
  inject,
  PLATFORM_ID,
  signal,
} from '@angular/core';
import {
  Router,
  RouterOutlet,
  RouterLink,
  RouterLinkActive,
  NavigationEnd,
} from '@angular/router';
import { isPlatformBrowser } from '@angular/common';
import { filter } from 'rxjs/operators';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Menu,
  X,
  LogIn,
  LogOut,
  LayoutDashboard,
  FilePen,
  Search,
  ChevronDown,
  Github,
  Linkedin,
  Twitter,
  Mail,
} from 'lucide-angular';
import { BackToTopComponent } from './shared/back-to-top/back-to-top.component';
import { SearchComponent } from './shared/search/search.component';
import { AuthService } from './core/services/auth.service';
import { slideDown } from './shared/animations/fade-in.animation';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    LucideAngularModule,
    BackToTopComponent,
    SearchComponent,
  ],
  templateUrl: './app.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [slideDown],
})
export class AppComponent {
  protected readonly title = 'Koopa';

  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly platformId = inject(PLATFORM_ID);

  protected readonly isAuthenticated = this.authService.isAuthenticated;
  protected readonly currentUser = this.authService.currentUser;

  protected readonly isMobileMenuOpen = signal(false);
  protected readonly isSearchOpen = signal(false);
  protected readonly isWritingMenuOpen = signal(false);
  protected readonly currentYear = new Date().getFullYear();

  // Lucide icons
  protected readonly MenuIcon = Menu;
  protected readonly XIcon = X;
  protected readonly LogInIcon = LogIn;
  protected readonly LogOutIcon = LogOut;
  protected readonly DashboardIcon = LayoutDashboard;
  protected readonly EditIcon = FilePen;
  protected readonly SearchIcon = Search;
  protected readonly ChevronDownIcon = ChevronDown;
  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly TwitterIcon = Twitter;
  protected readonly MailIcon = Mail;

  constructor() {
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
        this.isMobileMenuOpen.set(false);
        this.isSearchOpen.set(false);
        this.isWritingMenuOpen.set(false);
      });
  }

  protected toggleMobileMenu(): void {
    this.isMobileMenuOpen.update((v) => !v);
    if (this.isMobileMenuOpen()) {
      this.isSearchOpen.set(false);
    }
  }

  protected toggleSearch(): void {
    this.isSearchOpen.update((v) => !v);
  }

  protected toggleWritingMenu(): void {
    this.isWritingMenuOpen.update((v) => !v);
  }

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }
}
