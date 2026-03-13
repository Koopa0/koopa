import {
  Component,
  ChangeDetectionStrategy,
  ElementRef,
  inject,
  PLATFORM_ID,
  signal,
  afterNextRender,
  viewChild,
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
  LogOut,
  LayoutDashboard,
  FilePen,
  Search,
  ChevronDown,
  Github,
  Linkedin,
  Mail,
} from 'lucide-angular';
import { BackToTopComponent } from './shared/back-to-top/back-to-top.component';
import { CommandPaletteComponent } from './shared/command-palette/command-palette.component';
import { ToastComponent } from './shared/toast/toast.component';
import { CommandPaletteService } from './shared/command-palette/command-palette.service';
import { AuthService } from './core/services/auth.service';
import { KeyboardShortcutsService } from './core/services/keyboard-shortcuts.service';
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
    CommandPaletteComponent,
    ToastComponent,
  ],
  templateUrl: './app.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [slideDown],
  host: {
    'class': 'flex min-h-dvh flex-col',
    '(document:click)': 'onDocumentClick($event)',
  },
})
export class AppComponent {
  protected readonly title = 'Koopa';

  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly keyboardShortcuts = inject(KeyboardShortcutsService);
  protected readonly commandPalette = inject(CommandPaletteService);

  protected readonly isAuthenticated = this.authService.isAuthenticated;
  protected readonly currentUser = this.authService.currentUser;

  protected readonly isMobileMenuOpen = signal(false);
  protected readonly isWritingMenuOpen = signal(false);
  protected readonly currentYear = new Date().getFullYear();

  private readonly writingDropdown = viewChild.required<ElementRef>('writingDropdown');

  // Lucide icons
  protected readonly MenuIcon = Menu;
  protected readonly XIcon = X;
  protected readonly LogOutIcon = LogOut;
  protected readonly DashboardIcon = LayoutDashboard;
  protected readonly EditIcon = FilePen;
  protected readonly SearchIcon = Search;
  protected readonly ChevronDownIcon = ChevronDown;
  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly MailIcon = Mail;

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
        this.isMobileMenuOpen.set(false);
        this.isWritingMenuOpen.set(false);
      });
  }

  protected toggleMobileMenu(): void {
    this.isMobileMenuOpen.update((v) => !v);
  }

  protected toggleWritingMenu(): void {
    this.isWritingMenuOpen.update((v) => !v);
  }

  protected onDocumentClick(event: MouseEvent): void {
    if (!this.isWritingMenuOpen()) {
      return;
    }
    const target = event.target as HTMLElement;
    const dropdownEl = this.writingDropdown().nativeElement;
    if (!dropdownEl.contains(target)) {
      this.isWritingMenuOpen.set(false);
    }
  }

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }
}
