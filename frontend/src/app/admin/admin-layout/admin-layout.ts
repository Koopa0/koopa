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
  Sun,
  Target,
  FolderOpen,
  BookOpen,
  FileText,
  PenLine,
  Rss,
  Inbox,
  Menu,
  LogOut,
  PanelLeftClose,
  PanelLeft,
  ChevronDown,
  ChevronRight,
  Brain,
  Clock,
  NotebookPen,
  CalendarCheck,
  Lightbulb,
  ScrollText,
  Users,
  HeartPulse,
} from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { ToastComponent } from '../../shared/toast/toast.component';

interface NavItem {
  label: string;
  route: string;
  icon: typeof Sun;
  exact: boolean;
  disabled: boolean;
  badge?: number;
}

interface NavGroup {
  title: string;
  items: NavItem[];
  collapsible: boolean;
  collapsed?: boolean;
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
  protected readonly PanelLeftCloseIcon = PanelLeftClose;
  protected readonly PanelLeftIcon = PanelLeft;
  protected readonly MenuIcon = Menu;
  protected readonly ChevronDownIcon = ChevronDown;
  protected readonly ChevronRightIcon = ChevronRight;

  protected readonly navGroups: NavGroup[] = [
    {
      title: '',
      collapsible: false,
      items: [
        {
          label: 'Overview',
          route: '/admin/overview',
          icon: Sun,
          exact: true,
          disabled: false,
        },
      ],
    },
    {
      title: 'Activity',
      collapsible: true,
      items: [
        {
          label: 'Daily',
          route: '/admin/activity/daily',
          icon: NotebookPen,
          exact: false,
          disabled: false,
        },
        {
          label: 'Weekly',
          route: '/admin/activity/weekly',
          icon: CalendarCheck,
          exact: false,
          disabled: false,
        },
        {
          label: 'Insights',
          route: '/admin/activity/insights',
          icon: Lightbulb,
          exact: false,
          disabled: false,
        },
        {
          label: 'Journal',
          route: '/admin/activity/journal',
          icon: ScrollText,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Commitments',
      collapsible: true,
      items: [
        {
          label: 'Goals',
          route: '/admin/commitments/goals',
          icon: Target,
          exact: false,
          disabled: false,
        },
        {
          label: 'Projects',
          route: '/admin/commitments/projects',
          icon: FolderOpen,
          exact: false,
          disabled: false,
        },
        {
          label: 'Directives',
          route: '/admin/commitments/directives',
          icon: Users,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Learn',
      collapsible: true,
      items: [
        {
          label: 'Weaknesses',
          route: '/admin/learn/weaknesses',
          icon: Brain,
          exact: false,
          disabled: false,
        },
        {
          label: 'Sessions',
          route: '/admin/learn/sessions',
          icon: Clock,
          exact: false,
          disabled: false,
        },
        {
          label: 'Plans',
          route: '/admin/learn/plans',
          icon: BookOpen,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Content',
      collapsible: true,
      items: [
        {
          label: 'Pipeline',
          route: '/admin/content/pipeline',
          icon: PenLine,
          exact: false,
          disabled: false,
        },
        {
          label: 'Library',
          route: '/admin/content/library',
          icon: FileText,
          exact: false,
          disabled: false,
        },
        {
          label: 'Intelligence',
          route: '/admin/content/intelligence',
          icon: Rss,
          exact: false,
          disabled: false,
        },
        {
          label: 'Collected',
          route: '/admin/content/collected',
          icon: Inbox,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'System',
      collapsible: true,
      collapsed: true,
      items: [
        {
          label: 'Health',
          route: '/admin/system',
          icon: HeartPulse,
          exact: false,
          disabled: false,
        },
      ],
    },
  ];

  protected readonly collapsedGroups = signal<Set<string>>(new Set(['System']));

  constructor() {
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

  protected toggleGroup(title: string): void {
    this.collapsedGroups.update((set) => {
      const next = new Set(set);
      if (next.has(title)) {
        next.delete(title);
      } else {
        next.add(title);
      }
      return next;
    });
  }

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }
}
