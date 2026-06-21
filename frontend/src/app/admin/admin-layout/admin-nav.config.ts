import {
  Activity as ActivityIcon,
  Bot,
  Calendar,
  ChartColumn,
  CheckSquare,
  FileText,
  FolderKanban,
  HeartPulse,
  Home,
  Inbox as InboxIcon,
  Layers,
  Library,
  Moon,
  Music,
  Rss,
  Search,
  Sparkles,
  StickyNote,
  Tag,
  Target,
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
   * on "index" routes whose URL is a prefix of sibling nav items;
   * without it, RouterLinkActive's default prefix match keeps the index
   * item highlighted on every descendant route.
   */
  exact?: boolean;
}

export interface AdminNavGroup {
  label: string;
  items: AdminNavItem[];
}

/**
 * 4-domain nav structure (Daily / Commitment / Knowledge / System) per
 * the Mission Control design IA. Kept here, not inlined in
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
        label: 'Inbox',
        route: '/admin/daily/inbox',
        icon: InboxIcon,
        shortcutHint: '',
        testId: 'admin-nav-inbox',
      },
      {
        label: 'Todos',
        route: '/admin/daily/todos',
        icon: CheckSquare,
        countKey: 'todos_open',
        shortcutHint: 'G T',
        testId: 'admin-nav-todos',
      },
      {
        label: 'Day close',
        route: '/admin/daily/close',
        icon: Moon,
        shortcutHint: '',
        testId: 'admin-nav-day-close',
      },
    ],
  },
  {
    label: 'Commitment',
    items: [
      {
        label: 'Goals',
        route: '/admin/commitment/goals',
        icon: Target,
        countKey: 'goals_active',
        shortcutHint: 'G G',
        testId: 'admin-nav-goals',
      },
      {
        label: 'Projects',
        route: '/admin/commitment/projects',
        icon: FolderKanban,
        shortcutHint: '',
        testId: 'admin-nav-projects',
      },
      {
        label: 'Areas',
        route: '/admin/commitment/areas',
        icon: Layers,
        shortcutHint: '',
        testId: 'admin-nav-areas',
      },
      {
        label: 'Proposals',
        route: '/admin/commitment/proposals',
        icon: Sparkles,
        countKey: 'proposals_pending',
        shortcutHint: '',
        testId: 'admin-nav-proposals',
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
        label: 'Reading',
        route: '/admin/knowledge/reading',
        icon: Library,
        shortcutHint: '',
        testId: 'admin-nav-reading',
      },
      {
        label: 'ヨルシカ',
        route: '/admin/knowledge/song',
        icon: Music,
        shortcutHint: '',
        testId: 'admin-nav-song',
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
