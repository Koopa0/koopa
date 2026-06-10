import {
  Activity as ActivityIcon,
  BookOpen,
  Bot,
  Brain,
  Calendar,
  ChartColumn,
  CheckSquare,
  Compass,
  FileText,
  HeartPulse,
  Home,
  Layers,
  ListChecks,
  Rss,
  Search,
  StickyNote,
  Tag,
  Target,
  Timer,
} from 'lucide-angular';
import type { NavCountKey } from './admin-nav-counts.service';

/** Descriptor for one row in the admin nav rail. */
export interface AdminNavItem {
  label: string;
  route: string;
  icon: typeof Home;
  /**
   * Key into {@link AdminNavCountsService}'s envelope. Items without a
   * key render without a count (e.g. Today, Dashboard — entrypoints
   * whose count is not meaningful).
   */
  countKey?: NavCountKey;
  /**
   * Two-key chord hint (e.g. `G T`); chord binding lives in the service.
   * Empty string = no chord assigned (placeholder surfaces).
   */
  shortcutHint: string;
  /** Stable test id; avoids computing one from the label at render time. */
  testId: string;
  /**
   * Require an exact URL match for the active-state highlight. Set this
   * on "index" routes whose URL is a prefix of sibling nav items (e.g.
   * `/admin/learning` is a prefix of `/admin/learning/concepts`); without
   * it, RouterLinkActive's default prefix match keeps the index item
   * highlighted on every descendant route.
   */
  exact?: boolean;
}

export interface AdminNavGroup {
  label: string;
  items: AdminNavItem[];
}

/**
 * 5-domain nav structure (Daily / Commitment / Knowledge / Learning /
 * System) per the Mission Control design IA. Kept here, not inlined in
 * AdminLayoutComponent, so the component stays small and the structure
 * is reusable by tests and the command palette.
 */
export const ADMIN_NAV: readonly AdminNavGroup[] = [
  {
    label: 'Daily',
    items: [
      {
        label: 'Today',
        route: '/admin/daily/today',
        icon: Home,
        shortcutHint: 'G H',
        testId: 'admin-nav-today',
      },
      {
        label: 'Plan',
        route: '/admin/daily/plan',
        icon: Calendar,
        shortcutHint: '',
        testId: 'admin-nav-plan',
      },
      {
        label: 'Todos',
        route: '/admin/daily/todos',
        icon: CheckSquare,
        countKey: 'todos_open',
        shortcutHint: 'G T',
        testId: 'admin-nav-todos',
      },
    ],
  },
  {
    label: 'Commitment',
    items: [
      {
        label: 'Goals & projects',
        route: '/admin/commitment/goals',
        icon: Target,
        countKey: 'goals_active',
        shortcutHint: 'G G',
        testId: 'admin-nav-goals',
      },
    ],
  },
  {
    label: 'Knowledge',
    items: [
      {
        label: 'Content',
        route: '/admin/knowledge/content',
        icon: FileText,
        countKey: 'contents_total',
        shortcutHint: 'G C',
        testId: 'admin-nav-content',
      },
      {
        label: 'Review queue',
        route: '/admin/knowledge/review-queue',
        icon: CheckSquare,
        countKey: 'review_queue',
        shortcutHint: 'G R',
        testId: 'admin-nav-review-queue',
      },
      {
        label: 'Notes',
        route: '/admin/knowledge/notes',
        icon: StickyNote,
        shortcutHint: 'G N',
        testId: 'admin-nav-notes',
      },
      {
        label: 'Feeds',
        route: '/admin/knowledge/feeds',
        icon: Rss,
        countKey: 'feeds_active',
        shortcutHint: 'G F',
        testId: 'admin-nav-feeds',
      },
      {
        label: 'Search',
        route: '/admin/knowledge/search',
        icon: Search,
        shortcutHint: '',
        testId: 'admin-nav-search',
      },
      {
        label: 'Tags & topics',
        route: '/admin/knowledge/tags',
        icon: Tag,
        shortcutHint: '',
        testId: 'admin-nav-tags',
      },
    ],
  },
  {
    label: 'Learning',
    items: [
      {
        label: 'Dashboard',
        route: '/admin/learning',
        icon: Brain,
        shortcutHint: 'G L',
        testId: 'admin-nav-learning',
        exact: true,
      },
      {
        label: 'Sessions',
        route: '/admin/learning/sessions',
        icon: Timer,
        shortcutHint: '',
        testId: 'admin-nav-sessions',
      },
      {
        label: 'Domains',
        route: '/admin/learning/domains',
        icon: Layers,
        shortcutHint: 'G D',
        testId: 'admin-nav-domains',
      },
      {
        label: 'Concepts',
        route: '/admin/learning/concepts',
        icon: Compass,
        shortcutHint: 'G P',
        testId: 'admin-nav-concepts',
      },
      {
        label: 'Plans',
        route: '/admin/learning/plans',
        icon: ListChecks,
        shortcutHint: 'G S',
        testId: 'admin-nav-plans',
      },
      {
        label: 'Hypotheses',
        route: '/admin/learning/hypotheses',
        icon: BookOpen,
        countKey: 'hypotheses_unverified',
        shortcutHint: 'G Y',
        testId: 'admin-nav-hypotheses',
      },
    ],
  },
  {
    label: 'System',
    items: [
      {
        label: 'Health',
        route: '/admin/system/health',
        icon: HeartPulse,
        shortcutHint: '',
        testId: 'admin-nav-health',
      },
      {
        label: 'Stats',
        route: '/admin/system/stats',
        icon: ChartColumn,
        shortcutHint: '',
        testId: 'admin-nav-stats',
      },
      {
        label: 'Activity',
        route: '/admin/system/activity',
        icon: ActivityIcon,
        shortcutHint: 'G A',
        testId: 'admin-nav-activity',
      },
      {
        label: 'Agents',
        route: '/admin/system/agents',
        icon: Bot,
        shortcutHint: '',
        testId: 'admin-nav-agents',
      },
    ],
  },
] as const;
