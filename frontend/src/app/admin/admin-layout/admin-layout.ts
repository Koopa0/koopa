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
  Inbox,
  Target,
  FolderOpen,
  ListTodo,
  BookOpen,
  FileText,
  PenLine,
  Rss,
  Tags,
  Activity,
  Menu,
  LogOut,
  PanelLeftClose,
  PanelLeft,
  ChevronDown,
  ChevronRight,
  GraduationCap,
  Brain,
  RotateCcw,
  NotebookPen,
  CalendarCheck,
  Lightbulb,
  ScrollText,
  Users,
  HeartPulse,
  BarChart3,
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
          label: 'Today',
          route: '/admin/today',
          icon: Sun,
          exact: true,
          disabled: false,
        },
        {
          label: 'Dashboard',
          route: '/admin/dashboard',
          icon: BarChart3,
          exact: true,
          disabled: false,
        },
        {
          label: 'Inbox',
          route: '/admin/inbox',
          icon: Inbox,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Plan',
      collapsible: true,
      items: [
        {
          label: 'Goals',
          route: '/admin/plan/goals',
          icon: Target,
          exact: false,
          disabled: false,
        },
        {
          label: 'Projects',
          route: '/admin/plan/projects',
          icon: FolderOpen,
          exact: false,
          disabled: false,
        },
        {
          label: 'Tasks',
          route: '/admin/plan/tasks',
          icon: ListTodo,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Library',
      collapsible: true,
      items: [
        {
          label: 'Pipeline',
          route: '/admin/library/pipeline',
          icon: PenLine,
          exact: false,
          disabled: false,
        },
        {
          label: 'Contents',
          route: '/admin/library/contents',
          icon: FileText,
          exact: false,
          disabled: false,
        },
        {
          label: 'Editor',
          route: '/admin/library/editor',
          icon: BookOpen,
          exact: true,
          disabled: false,
        },
      ],
    },
    {
      title: 'Learn',
      collapsible: true,
      items: [
        {
          label: 'Dashboard',
          route: '/admin/learn/dashboard',
          icon: GraduationCap,
          exact: false,
          disabled: false,
        },
        {
          label: 'Concepts',
          route: '/admin/learn/concepts',
          icon: Brain,
          exact: false,
          disabled: false,
        },
        {
          label: 'Review',
          route: '/admin/learn/review',
          icon: RotateCcw,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Reflect',
      collapsible: true,
      items: [
        {
          label: 'Daily',
          route: '/admin/reflect/daily',
          icon: NotebookPen,
          exact: false,
          disabled: false,
        },
        {
          label: 'Weekly',
          route: '/admin/reflect/weekly',
          icon: CalendarCheck,
          exact: false,
          disabled: false,
        },
        {
          label: 'Insights',
          route: '/admin/reflect/insights',
          icon: Lightbulb,
          exact: false,
          disabled: false,
        },
        {
          label: 'Journal',
          route: '/admin/reflect/journal',
          icon: ScrollText,
          exact: false,
          disabled: false,
        },
      ],
    },
    {
      title: 'Coordinate',
      collapsible: true,
      collapsed: true,
      items: [
        {
          label: 'Studio',
          route: '/admin/studio',
          icon: Users,
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
          route: '/admin/system/health',
          icon: HeartPulse,
          exact: false,
          disabled: false,
        },
        {
          label: 'Feeds',
          route: '/admin/system/feeds',
          icon: Rss,
          exact: false,
          disabled: false,
        },
        {
          label: 'Tags',
          route: '/admin/system/tags',
          icon: Tags,
          exact: false,
          disabled: false,
        },
        {
          label: 'Activity',
          route: '/admin/system/activity',
          icon: Activity,
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
