import {
  Injectable,
  signal,
  computed,
  inject,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { Router } from '@angular/router';
import { forkJoin } from 'rxjs';
import { AuthService } from '../../core/services/auth.service';
import { PlanService } from '../../core/services/plan.service';
import { ContentService } from '../../core/services/content.service';

export interface CommandAction {
  id: string;
  label: string;
  group: string;
  keywords?: string[];
  action: () => void;
}

/**
 * Admin nav quick-jumps mirror Kept as a
 * flat array because the palette consumer is a single `actions()`
 * list; if ADMIN_NAV (admin-nav.config.ts) ever becomes the canonical
 * source, swap this for a map() over it.
 */
interface AdminNavActionEntry {
  id: string;
  label: string;
  group: string;
  path: string;
  keywords: string[];
}

const ADMIN_NAV_ACTIONS: readonly AdminNavActionEntry[] = [
  {
    id: 'admin-today',
    label: 'Today',
    group: 'Commitment',
    path: '/admin/commitment/today',
    keywords: ['home', 'plan', 'judgment'],
  },
  {
    id: 'admin-todos',
    label: 'Todos',
    group: 'Commitment',
    path: '/admin/commitment/todos',
    keywords: ['tasks', 'inbox'],
  },
  {
    id: 'admin-goals',
    label: 'Goals & projects',
    group: 'Commitment',
    path: '/admin/commitment/goals',
    keywords: ['goal', 'project', 'milestone'],
  },
  {
    id: 'admin-content',
    label: 'Content',
    group: 'Knowledge',
    path: '/admin/knowledge/content',
    keywords: ['articles', 'essays', 'til', 'digest'],
  },
  {
    id: 'admin-review-queue',
    label: 'Review queue',
    group: 'Knowledge',
    path: '/admin/knowledge/review-queue',
    keywords: ['review', 'drafts', 'approve'],
  },
  {
    id: 'admin-notes',
    label: 'Notes',
    group: 'Knowledge',
    path: '/admin/knowledge/notes',
    keywords: ['zettelkasten', 'knowledge'],
  },
  {
    id: 'admin-bookmarks',
    label: 'Bookmarks',
    group: 'Knowledge',
    path: '/admin/knowledge/bookmarks',
    keywords: ['links', 'collected'],
  },
  {
    id: 'admin-feeds',
    label: 'Feeds',
    group: 'Knowledge',
    path: '/admin/knowledge/feeds',
    keywords: ['rss', 'sources'],
  },
  {
    id: 'admin-feeds-triage',
    label: 'Feed triage',
    group: 'Knowledge',
    path: '/admin/knowledge/feeds/triage',
    keywords: ['inbox', 'triage'],
  },
  {
    id: 'admin-learning',
    label: 'Learning dashboard',
    group: 'Learning',
    path: '/admin/learning',
    keywords: ['mastery', 'concepts'],
  },
  {
    id: 'admin-concepts',
    label: 'Concepts',
    group: 'Learning',
    path: '/admin/learning/concepts',
    keywords: ['mastery', 'weakness'],
  },
  {
    id: 'admin-hypotheses',
    label: 'Hypotheses',
    group: 'Learning',
    path: '/admin/learning/hypotheses',
    keywords: ['claim', 'verify'],
  },
  {
    id: 'admin-tasks',
    label: 'Tasks',
    group: 'Coordination',
    path: '/admin/coordination/tasks',
    keywords: ['directive', 'assigned'],
  },
  {
    id: 'admin-agents',
    label: 'Agents',
    group: 'Coordination',
    path: '/admin/coordination/agents',
    keywords: ['agent', 'cowork'],
  },
  {
    id: 'admin-pipeline',
    label: 'Process runs',
    group: 'Coordination',
    path: '/admin/coordination/pipeline',
    keywords: ['pipeline', 'runs'],
  },
  {
    id: 'admin-activity',
    label: 'Activity',
    group: 'Coordination',
    path: '/admin/coordination/activity',
    keywords: ['changelog', 'audit'],
  },
];

@Injectable({ providedIn: 'root' })
export class CommandPaletteService {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);
  private readonly planService = inject(PlanService);
  private readonly contentService = inject(ContentService);
  private readonly platformId = inject(PLATFORM_ID);

  private readonly _isOpen = signal(false);
  readonly isOpen = this._isOpen.asReadonly();

  readonly isAuthenticated = this.authService.isAuthenticated;

  private readonly _adminEntities = signal<CommandAction[]>([]);
  private hasLoadedEntities = false;

  /** All available actions based on auth state */
  readonly actions = computed<CommandAction[]>(() => {
    const pages: CommandAction[] = [
      {
        id: 'home',
        label: 'Home',
        group: 'Pages',
        keywords: ['index', 'main'],
        action: () => this.navigate('/'),
      },
      {
        id: 'articles',
        label: 'Articles',
        group: 'Pages',
        keywords: ['blog', 'post', 'writing'],
        action: () => this.navigate('/articles'),
      },
      {
        id: 'til',
        label: 'TIL',
        group: 'Pages',
        keywords: ['today', 'learned', 'learning'],
        action: () => this.navigate('/til'),
      },
      {
        id: 'projects',
        label: 'Projects',
        group: 'Pages',
        keywords: ['portfolio', 'work'],
        action: () => this.navigate('/projects'),
      },
      {
        id: 'uses',
        label: 'Uses',
        group: 'Pages',
        keywords: ['tools', 'setup', 'stack'],
        action: () => this.navigate('/uses'),
      },
      {
        id: 'about',
        label: 'About',
        group: 'Pages',
        keywords: ['me', 'info', 'cv', 'experience', 'resume'],
        action: () => this.navigate('/about'),
      },
    ];

    if (this.isAuthenticated()) {
      const admin: CommandAction[] = ADMIN_NAV_ACTIONS.map((entry) => ({
        id: entry.id,
        label: entry.label,
        group: entry.group,
        keywords: entry.keywords,
        action: () => this.navigate(entry.path),
      }));
      return [...pages, ...admin, ...this._adminEntities()];
    }

    return pages;
  });

  open(): void {
    this._isOpen.set(true);
    this.loadAdminEntitiesIfNeeded();
  }

  close(): void {
    this._isOpen.set(false);
  }

  toggle(): void {
    this._isOpen.update((v) => !v);
    if (this._isOpen()) {
      this.loadAdminEntitiesIfNeeded();
    }
  }

  private navigate(path: string): void {
    this.router.navigate([path]);
  }

  private loadAdminEntitiesIfNeeded(): void {
    if (
      !isPlatformBrowser(this.platformId) ||
      !this.isAuthenticated() ||
      this.hasLoadedEntities
    ) {
      return;
    }

    this.hasLoadedEntities = true;

    forkJoin({
      goals: this.planService.getGoalsOverview(),
      projects: this.planService.getProjectsOverview(),
      contents: this.contentService.adminList({ perPage: 50 }),
    }).subscribe({
      next: ({ goals, projects, contents }) => {
        const goalActions: CommandAction[] = goals.goals.map((g) => ({
          id: `goal:${g.id}`,
          label: g.title,
          group: 'Goals',
          keywords: [g.area_name, g.quarter].filter(
            (k): k is string => typeof k === 'string' && k.length > 0,
          ),
          action: () => this.navigate(`/admin/commitment/goals/${g.id}`),
        }));

        const projectActions: CommandAction[] = projects.projects.map((p) => ({
          id: `project:${p.id}`,
          label: p.title,
          group: 'Projects',
          keywords: [p.area, p.status],
          action: () => this.navigate(`/admin/commitment/projects/${p.id}`),
        }));

        const contentActions: CommandAction[] = contents.data
          .filter((c) => c.status !== 'archived')
          .map((c) => ({
            id: `content:${c.id}`,
            label: c.title,
            group: 'Content',
            keywords: [c.type, c.status, c.slug],
            action: () =>
              this.navigate(`/admin/knowledge/content/${c.id}/edit`),
          }));

        this._adminEntities.set([
          ...goalActions,
          ...projectActions,
          ...contentActions,
        ]);
      },
      error: () => {
        this.hasLoadedEntities = false;
      },
    });
  }
}
