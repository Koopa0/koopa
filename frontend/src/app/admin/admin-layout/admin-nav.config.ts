import {
  Activity as ActivityIcon,
  BookOpen,
  Bookmark as BookmarkIcon,
  Brain,
  CheckSquare,
  Compass,
  FileText,
  GitBranch,
  Home,
  MessageSquare,
  Rss,
  StickyNote,
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
  /** Two-key chord hint (e.g. `G T`); chord binding lives in the service. */
  shortcutHint: string;
  /** Stable test id; avoids computing one from the label at render time. */
  testId: string;
}

export interface AdminNavGroup {
  label: string;
  items: AdminNavItem[];
}

/**
 * 4-domain nav structure. Mirrors the backend's semantic subsystems
 * (Commitment / Knowledge / Learning / Coordination). Kept here, not
 * inlined in AdminLayoutComponent, so the component stays small and
 * the structure is reusable by tests and the command palette.
 */
export const ADMIN_NAV: readonly AdminNavGroup[] = [
  {
    label: 'Commitment',
    items: [
      {
        label: 'Today',
        route: '/admin/commitment/today',
        icon: Home,
        shortcutHint: 'G H',
        testId: 'admin-nav-today',
      },
      {
        label: 'Todos',
        route: '/admin/commitment/todos',
        icon: CheckSquare,
        countKey: 'todos_open',
        shortcutHint: 'G T',
        testId: 'admin-nav-todos',
      },
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
        label: 'Bookmarks',
        route: '/admin/knowledge/bookmarks',
        icon: BookmarkIcon,
        countKey: 'bookmarks_total',
        shortcutHint: 'G B',
        testId: 'admin-nav-bookmarks',
      },
      {
        label: 'Feeds',
        route: '/admin/knowledge/feeds',
        icon: Rss,
        countKey: 'feeds_active',
        shortcutHint: 'G F',
        testId: 'admin-nav-feeds',
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
      },
      {
        label: 'Concepts',
        route: '/admin/learning/concepts',
        icon: Compass,
        shortcutHint: 'G P',
        testId: 'admin-nav-concepts',
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
    label: 'Coordination',
    items: [
      {
        label: 'Tasks',
        route: '/admin/coordination/tasks',
        icon: MessageSquare,
        countKey: 'tasks_awaiting_human',
        shortcutHint: 'G K',
        testId: 'admin-nav-tasks',
      },
      {
        label: 'Process runs',
        route: '/admin/coordination/pipeline',
        icon: GitBranch,
        shortcutHint: '',
        testId: 'admin-nav-pipeline',
      },
      {
        label: 'Activity',
        route: '/admin/coordination/activity',
        icon: ActivityIcon,
        shortcutHint: 'G A',
        testId: 'admin-nav-activity',
      },
    ],
  },
] as const;
