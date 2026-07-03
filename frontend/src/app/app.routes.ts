import { Routes } from '@angular/router';
import { adminGuard } from './core/guards/auth.guard';
import { contentEditorCanDeactivate } from './admin/knowledge/content/editor/content-editor.guard';
import { articleResolver } from './pages/article-detail/article-resolver';

export const routes: Routes = [
  // The front door — a three-band editorial home (positioning statement,
  // themes-as-list, recent pieces). The full reading wall lives at /articles.
  {
    path: '',
    pathMatch: 'full',
    loadComponent: () =>
      import('./pages/home/home').then((m) => m.HomeComponent),
  },
  { path: 'home', redirectTo: '/', pathMatch: 'full' },
  {
    path: 'articles',
    loadComponent: () =>
      import('./pages/articles/articles').then((m) => m.ArticlesComponent),
  },
  {
    path: 'articles/:slug',
    loadComponent: () =>
      import('./pages/article-detail/article-detail').then(
        (m) => m.ArticleDetailComponent,
      ),
    resolve: { article: articleResolver },
  },
  // Chrome-less render of the same reading surface for the admin
  // publish-preview iframe (no header / footer / TOC / nav).
  {
    path: 'preview/:slug',
    loadComponent: () =>
      import('./pages/article-detail/article-detail').then(
        (m) => m.ArticleDetailComponent,
      ),
    data: { preview: true },
    resolve: { article: articleResolver },
  },
  {
    path: 'topics',
    loadComponent: () =>
      import('./pages/topics/topics').then((m) => m.TopicsComponent),
  },
  {
    path: 'topics/:slug',
    loadComponent: () =>
      import('./pages/topic-detail/topic-detail').then(
        (m) => m.TopicDetailComponent,
      ),
  },
  {
    path: 'search',
    loadComponent: () =>
      import('./pages/search/search').then((m) => m.SearchComponent),
  },
  {
    path: 'resume',
    redirectTo: '/about',
    pathMatch: 'full',
  },
  {
    path: 'about',
    loadComponent: () =>
      import('./pages/about/about').then((m) => m.AboutComponent),
  },
  {
    path: 'hire',
    loadComponent: () =>
      import('./pages/hire/hire').then((m) => m.HireComponent),
  },
  {
    path: 'privacy',
    loadComponent: () =>
      import('./pages/privacy/privacy').then((m) => m.PrivacyComponent),
  },
  {
    path: 'terms',
    loadComponent: () =>
      import('./pages/terms/terms').then((m) => m.TermsComponent),
  },
  {
    path: 'login',
    loadComponent: () =>
      import('./pages/login/login').then((m) => m.LoginComponent),
  },
  {
    path: 'admin/oauth-callback',
    loadComponent: () => import('./admin/oauth-callback/oauth-callback'),
  },
  {
    path: 'admin',
    loadComponent: () =>
      import('./admin/admin-layout/admin-layout').then(
        (m) => m.AdminLayoutComponent,
      ),
    canActivate: [adminGuard],
    children: [
      { path: '', redirectTo: 'daily/today', pathMatch: 'full' },

      // ── Daily ────────────────────────────────────────────────────
      {
        path: 'daily/today',
        loadComponent: () =>
          import('./admin/commitment/today/today-page.component').then(
            (m) => m.TodayPageComponent,
          ),
      },
      {
        path: 'daily/plan',
        loadComponent: () =>
          import('./admin/daily/plan/daily-plan.page').then(
            (m) => m.DailyPlanPageComponent,
          ),
      },
      {
        path: 'daily/inbox',
        loadComponent: () =>
          import('./admin/commitment/inbox/inbox.page').then(
            (m) => m.InboxPageComponent,
          ),
      },
      {
        path: 'daily/todos',
        loadComponent: () =>
          import('./admin/commitment/todos/gtd.page').then(
            (m) => m.GtdPageComponent,
          ),
        data: { gtdView: 'pending' },
      },
      {
        path: 'daily/routines',
        loadComponent: () =>
          import('./admin/commitment/routines/routines.page').then(
            (m) => m.RoutinesPageComponent,
          ),
      },

      // ── Commitment ───────────────────────────────────────────────
      {
        path: 'commitment/goals',
        loadComponent: () =>
          import('./admin/commitment/goals/list/goals-list.page').then(
            (m) => m.GoalsListPageComponent,
          ),
      },
      {
        path: 'commitment/goals/new',
        loadComponent: () =>
          import('./admin/commitment/goals/create/goal-create.page').then(
            (m) => m.GoalCreatePageComponent,
          ),
      },
      {
        path: 'commitment/goals/:id',
        loadComponent: () =>
          import('./admin/commitment/goals/profile/goal-profile.page').then(
            (m) => m.GoalProfilePageComponent,
          ),
      },
      {
        path: 'commitment/proposals',
        loadComponent: () =>
          import('./admin/commitment/proposals/proposals-triage.page').then(
            (m) => m.ProposalsTriagePageComponent,
          ),
      },
      {
        path: 'commitment/projects',
        loadComponent: () =>
          import('./admin/commitment/projects/list/projects-list.page').then(
            (m) => m.ProjectsListPageComponent,
          ),
      },
      {
        path: 'commitment/projects/new',
        loadComponent: () =>
          import('./admin/commitment/projects/create/project-create.page').then(
            (m) => m.ProjectCreatePageComponent,
          ),
      },
      {
        path: 'commitment/projects/:id',
        loadComponent: () =>
          import('./admin/commitment/projects/profile/project-profile.page').then(
            (m) => m.ProjectProfilePageComponent,
          ),
      },
      {
        path: 'commitment/areas',
        loadComponent: () =>
          import('./admin/commitment/areas/list/areas-list.page').then(
            (m) => m.AreasListPageComponent,
          ),
      },
      {
        path: 'commitment/areas/new',
        loadComponent: () =>
          import('./admin/commitment/areas/create/area-create.page').then(
            (m) => m.AreaCreatePageComponent,
          ),
      },
      {
        path: 'commitment/areas/:id',
        loadComponent: () =>
          import('./admin/commitment/areas/detail/area-detail.page').then(
            (m) => m.AreaDetailPageComponent,
          ),
      },

      // ── Knowledge ────────────────────────────────────────────────
      {
        path: 'knowledge/content',
        loadComponent: () =>
          import('./admin/knowledge/content/list/content-list.page').then(
            (m) => m.ContentListPageComponent,
          ),
        data: { title: 'All content', crumbs: ['Knowledge', 'Content'] },
      },
      {
        path: 'knowledge/content/new',
        loadComponent: () =>
          import('./admin/knowledge/content/editor/content-editor.page').then(
            (m) => m.ContentEditorPageComponent,
          ),
        canDeactivate: [contentEditorCanDeactivate],
      },
      {
        path: 'knowledge/content/:id/edit',
        loadComponent: () =>
          import('./admin/knowledge/content/editor/content-editor.page').then(
            (m) => m.ContentEditorPageComponent,
          ),
        canDeactivate: [contentEditorCanDeactivate],
      },
      {
        path: 'knowledge/review-queue',
        loadComponent: () =>
          import('./admin/knowledge/content/list/content-list.page').then(
            (m) => m.ContentListPageComponent,
          ),
        data: {
          title: 'Review queue',
          crumbs: ['Knowledge', 'Review queue'],
          initialStatus: 'review',
        },
      },
      {
        path: 'knowledge/feeds',
        loadComponent: () =>
          import('./admin/knowledge/feeds/list/feeds-list.page').then(
            (m) => m.FeedsListPageComponent,
          ),
      },
      {
        path: 'knowledge/feeds/triage',
        loadComponent: () =>
          import('./admin/knowledge/feeds/triage/feed-triage.page').then(
            (m) => m.FeedTriagePageComponent,
          ),
      },
      {
        path: 'knowledge/search',
        loadComponent: () =>
          import('./admin/knowledge/search/knowledge-search.page').then(
            (m) => m.KnowledgeSearchPageComponent,
          ),
      },
      {
        path: 'knowledge/topics',
        loadComponent: () =>
          import('./admin/knowledge/topics/topics.page').then(
            (m) => m.TopicsPageComponent,
          ),
      },

      // ── System ───────────────────────────────────────────────────
      {
        path: 'system/health',
        loadComponent: () =>
          import('./admin/system/health/system-health.page').then(
            (m) => m.SystemHealthPageComponent,
          ),
      },
      {
        path: 'system/stats',
        loadComponent: () =>
          import('./admin/system/stats/system-stats.page').then(
            (m) => m.SystemStatsPageComponent,
          ),
      },
      {
        path: 'system/activity',
        loadComponent: () =>
          import('./admin/system/activity/activity.page').then(
            (m) => m.ActivityPageComponent,
          ),
      },
      {
        path: 'system/agents',
        loadComponent: () =>
          import('./admin/system/agents/list/agents-list.page').then(
            (m) => m.AgentsListPageComponent,
          ),
      },
      {
        path: 'system/agents/:name',
        loadComponent: () =>
          import('./admin/system/agents/profile/agent-profile.page').then(
            (m) => m.AgentProfilePageComponent,
          ),
      },

      // ── Retired-path redirects (old links keep working) ──────────
      {
        path: 'commitment/today',
        redirectTo: 'daily/today',
        pathMatch: 'full',
      },
      {
        path: 'commitment/todos',
        redirectTo: 'daily/todos',
        pathMatch: 'full',
      },
      {
        path: 'coordination/activity',
        redirectTo: 'system/activity',
        pathMatch: 'full',
      },
      {
        path: 'coordination/agents',
        redirectTo: 'system/agents',
        pathMatch: 'full',
      },
      {
        path: 'coordination/agents/:name',
        redirectTo: 'system/agents/:name',
      },

      // ── Legacy stub routes (redirect to v2 equivalents) ──────────
      { path: 'now', redirectTo: 'daily/today', pathMatch: 'full' },
      { path: 'atlas', redirectTo: 'knowledge/content', pathMatch: 'full' },
    ],
  },
  {
    path: 'error',
    loadComponent: () =>
      import('./pages/error/error.component').then((m) => m.ErrorComponent),
  },
  {
    path: '**',
    loadComponent: () =>
      import('./pages/not-found/not-found.component').then(
        (m) => m.NotFoundComponent,
      ),
  },
];
