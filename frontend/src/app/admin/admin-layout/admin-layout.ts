import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
} from '@angular/core';
import { BreakpointObserver } from '@angular/cdk/layout';
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
  Rss,
  Tags,
  Menu,
  LogOut,
  Home,
  PanelLeftClose,
  PanelLeft,
  FolderOpen,
  Target,
  FileText,
  Inbox,
} from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { ToastComponent } from '../../shared/toast/toast.component';

interface NavItem {
  label: string;
  route: string;
  icon: typeof LayoutDashboard;
  exact: boolean;
  disabled: boolean;
  queryParams?: Record<string, string>;
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
  private readonly breakpointObserver = inject(BreakpointObserver);

  protected readonly isSidebarOpen = signal(true);
  protected readonly isMobileSidebarOpen = signal(false);

  protected readonly LogOutIcon = LogOut;
  protected readonly HomeIcon = Home;
  protected readonly PanelLeftCloseIcon = PanelLeftClose;
  protected readonly PanelLeftIcon = PanelLeft;
  protected readonly MenuIcon = Menu;

  protected readonly navGroups: NavGroup[] = [
    {
      title: '總覽',
      items: [
        {
          label: 'Dashboard',
          route: '/admin',
          icon: LayoutDashboard,
          exact: true,
          disabled: false,
        },
      ],
    },
    {
      title: '內容',
      items: [
        {
          label: 'Library',
          route: '/admin/contents',
          icon: FileText,
          exact: false,
          disabled: false,
        },
        {
          label: 'Inbox',
          route: '/admin/inbox',
          icon: Inbox,
          exact: false,
          disabled: false,
        },
        {
          label: 'Feeds',
          route: '/admin/feeds',
          icon: Rss,
          exact: false,
          disabled: false,
        },
        {
          label: 'Tags',
          route: '/admin/tags',
          icon: Tags,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: '管理',
      items: [
        {
          label: 'Projects',
          route: '/admin/projects',
          icon: FolderOpen,
          exact: false,
          disabled: false,
        },
        {
          label: 'Goals',
          route: '/admin/goals',
          icon: Target,
          exact: false,
          disabled: false,
        },
        {
          label: 'Activity',
          route: '/admin/activity',
          icon: Activity,
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

    // 預設手機版收合（使用 CDK BreakpointObserver 取代 window.innerWidth）
    this.breakpointObserver
      .observe(['(max-width: 767.98px)'])
      .pipe(takeUntilDestroyed())
      .subscribe((result) => {
        if (result.matches) {
          this.isSidebarOpen.set(false);
        }
      });
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
