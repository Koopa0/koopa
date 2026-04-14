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

export interface CommandAction {
  id: string;
  label: string;
  group: string;
  keywords?: string[];
  action: () => void;
}

@Injectable({ providedIn: 'root' })
export class CommandPaletteService {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);
  private readonly planService = inject(PlanService);
  private readonly platformId = inject(PLATFORM_ID);

  private readonly _isOpen = signal(false);
  readonly isOpen = this._isOpen.asReadonly();

  readonly isAuthenticated = this.authService.isAuthenticated;

  // Dynamically loaded admin entities (goals + projects), fetched once
  // on first open while authenticated. Cleared implicitly on reload.
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
      const admin: CommandAction[] = [
        {
          id: 'admin-dashboard',
          label: 'Admin Dashboard',
          group: 'Admin',
          keywords: ['admin', 'manage', 'overview'],
          action: () => this.navigate('/admin'),
        },
      ];
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
    }).subscribe({
      next: ({ goals, projects }) => {
        const goalActions: CommandAction[] = goals.by_area.flatMap((area) =>
          area.goals.map((g) => ({
            id: `goal:${g.id}`,
            label: g.title,
            group: 'Goals',
            keywords: [area.area_name, g.quarter],
            action: () =>
              this.router.navigate(['/admin/commitments/goals'], {
                queryParams: { inspect: `goal:${g.id}` },
              }),
          })),
        );

        const projectActions: CommandAction[] = projects.projects.map((p) => ({
          id: `project:${p.id}`,
          label: p.title,
          group: 'Projects',
          keywords: [p.area, p.status],
          action: () =>
            this.router.navigate(['/admin/commitments/projects'], {
              queryParams: { inspect: `project:${p.id}` },
            }),
        }));

        this._adminEntities.set([...goalActions, ...projectActions]);
      },
      error: () => {
        // Silent fail — palette still works with static actions.
        // Reset so next open can retry.
        this.hasLoadedEntities = false;
      },
    });
  }
}
