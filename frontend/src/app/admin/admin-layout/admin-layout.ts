import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import {
  Router,
  RouterOutlet,
  RouterLink,
  RouterLinkActive,
  NavigationEnd,
} from '@angular/router';
import { filter } from 'rxjs/operators';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  LayoutDashboard,
  Activity,
  FileText,
  FolderOpen,
  Rss,
  Database,
  ClipboardCheck,
  Menu,
  LogOut,
  Home,
  PanelLeftClose,
  PanelLeft,
} from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { ToastComponent } from '../../shared/toast/toast.component';

interface NavItem {
  label: string;
  route: string;
  icon: typeof LayoutDashboard;
  exact: boolean;
  disabled: boolean;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

@Component({
  selector: 'app-admin-layout',
  standalone: true,
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    LucideAngularModule,
    ToastComponent,
  ],
  templateUrl: './admin-layout.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex h-[calc(100dvh-57px)]' },
})
export class AdminLayoutComponent {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);
  private readonly platformId = inject(PLATFORM_ID);

  protected readonly isSidebarOpen = signal(true);
  protected readonly isMobileSidebarOpen = signal(false);

  protected readonly LogOutIcon = LogOut;
  protected readonly HomeIcon = Home;
  protected readonly PanelLeftCloseIcon = PanelLeftClose;
  protected readonly PanelLeftIcon = PanelLeft;
  protected readonly MenuIcon = Menu;

  protected readonly navGroups: NavGroup[] = [
    {
      title: 'Overview',
      items: [
        {
          label: 'Dashboard',
          route: '/admin',
          icon: LayoutDashboard,
          exact: true,
          disabled: false,
        },
        {
          label: 'Flow Runs',
          route: '/admin/flow-runs',
          icon: Activity,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Pipeline',
      items: [
        {
          label: 'RSS Feeds',
          route: '/admin/feeds',
          icon: Rss,
          exact: false,
          disabled: false,
        },
        {
          label: 'Collected',
          route: '/admin/collected',
          icon: Database,
          exact: false,
          disabled: false,
        },
        {
          label: 'Review Queue',
          route: '/admin/review',
          icon: ClipboardCheck,
          exact: false,
          disabled: false,
        },
      ],
    },
  ];

  constructor() {
    // 手機版導航後自動收合
    this.router.events
      .pipe(
        filter(
          (event): event is NavigationEnd => event instanceof NavigationEnd,
        ),
        takeUntilDestroyed(),
      )
      .subscribe(() => {
        this.isMobileSidebarOpen.set(false);
      });

    // 預設手機版收合
    if (isPlatformBrowser(this.platformId)) {
      if (window.innerWidth < 768) {
        this.isSidebarOpen.set(false);
      }
    }
  }

  protected toggleSidebar(): void {
    this.isSidebarOpen.update((v) => !v);
  }

  protected toggleMobileSidebar(): void {
    this.isMobileSidebarOpen.update((v) => !v);
  }

  protected closeMobileSidebar(): void {
    this.isMobileSidebarOpen.set(false);
  }

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }

  protected backToSite(): void {
    this.router.navigate(['/']);
  }
}
