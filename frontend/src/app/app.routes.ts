import { Routes } from '@angular/router';
import { adminGuard } from './core/guards/auth.guard';
import { contentEditorCanDeactivate } from './admin/knowledge/content/editor/content-editor.guard';
import { noteEditorCanDeactivate } from './admin/knowledge/notes/editor/note-editor.guard';

export const routes: Routes = [
  // The articles index IS the home page — one consolidated reading index
  // for every written content type (article / essay / build-log / til /
  // digest), filterable via the `type` query param.
  {
    path: '',
    pathMatch: 'full',
    loadComponent: () =>
      import('./pages/articles/articles').then((m) => m.ArticlesComponent),
  },
  { path: 'home', redirectTo: '/', pathMatch: 'full' },
  {
    path: 'design-system',
    loadComponent: () =>
      import('./pages/design-system/design-system').then(
        (m) => m.DesignSystemComponent,
      ),
  },
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
  },
  // Retired per-type list pages — the consolidated index covers them.
  { path: 'essays', redirectTo: '/articles?type=essay', pathMatch: 'full' },
  { path: 'til', redirectTo: '/articles?type=til', pathMatch: 'full' },
  {
    path: 'build-logs',
    redirectTo: '/articles?type=build-log',
    pathMatch: 'full',
  },
  // Retired per-type detail pages — every content type reads at
  // /articles/:slug (one reading surface).
  { path: 'essays/:slug', redirectTo: '/articles/:slug' },
  { path: 'til/:slug', redirectTo: '/articles/:slug' },
  { path: 'build-logs/:slug', redirectTo: '/articles/:slug' },
  {
    path: 'projects',
    loadComponent: () =>
      import('./pages/projects/projects').then((m) => m.ProjectsComponent),
  },
  {
    path: 'projects/:slug',
    loadComponent: () =>
      import('./pages/project-detail/project-detail').then(
        (m) => m.ProjectDetailComponent,
      ),
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
    path: 'uses',
    loadComponent: () =>
      import('./pages/uses/uses').then((m) => m.UsesComponent),
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
          import('./admin/commitment/todos/gtd.page').then(
            (m) => m.GtdPageComponent,
          ),
        data: { gtdView: 'inbox' },
      },
      {
        path: 'daily/todos',
        loadComponent: () =>
          import('./admin/commitment/todos/gtd.page').then(
            (m) => m.GtdPageComponent,
          ),
        data: { gtdView: 'today' },
      },
      {
        path: 'daily/close',
        loadComponent: () =>
          import('./admin/commitment/day-close/day-close.page').then(
            (m) => m.DayClosePageComponent,
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
        path: 'commitment/projects/:id',
        loadComponent: () =>
          import('./admin/commitment/projects/profile/project-profile.page').then(
            (m) => m.ProjectProfilePageComponent,
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
        path: 'knowledge/notes',
        loadComponent: () =>
          import('./admin/knowledge/notes/list/notes-list.page').then(
            (m) => m.NotesListPageComponent,
          ),
      },
      {
        path: 'knowledge/notes/new',
        loadComponent: () =>
          import('./admin/knowledge/notes/editor/note-editor.page').then(
            (m) => m.NoteEditorPageComponent,
          ),
        canDeactivate: [noteEditorCanDeactivate],
      },
      {
        path: 'knowledge/notes/:id/edit',
        loadComponent: () =>
          import('./admin/knowledge/notes/editor/note-editor.page').then(
            (m) => m.NoteEditorPageComponent,
          ),
        canDeactivate: [noteEditorCanDeactivate],
      },
      {
        path: 'knowledge/reading',
        loadComponent: () =>
          import('./admin/knowledge/reading/shelf/reading-shelf.page').then(
            (m) => m.ReadingShelfPageComponent,
          ),
      },
      {
        path: 'knowledge/reading/:id',
        loadComponent: () =>
          import('./admin/knowledge/reading/detail/reading-detail.page').then(
            (m) => m.ReadingDetailPageComponent,
          ),
      },
      {
        path: 'knowledge/song',
        loadComponent: () =>
          import('./admin/knowledge/song/shelf/song-shelf.page').then(
            (m) => m.SongShelfPageComponent,
          ),
      },
      {
        path: 'knowledge/song/:id',
        loadComponent: () =>
          import('./admin/knowledge/song/detail/song-detail.page').then(
            (m) => m.SongDetailPageComponent,
          ),
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
        path: 'knowledge/tags',
        loadComponent: () =>
          import('./admin/knowledge/tags/tags-topics.page').then(
            (m) => m.TagsTopicsPageComponent,
          ),
      },

      // ── Learning ─────────────────────────────────────────────────
      {
        path: 'learning',
        pathMatch: 'full',
        loadComponent: () =>
          import('./admin/learning/dashboard/learning-dashboard.page').then(
            (m) => m.LearningDashboardPageComponent,
          ),
      },
      {
        path: 'learning/domains',
        loadComponent: () =>
          import('./admin/learning/domains/list/domains-list.page').then(
            (m) => m.DomainsListPageComponent,
          ),
      },
      {
        path: 'learning/domains/new',
        loadComponent: () =>
          import('./admin/learning/domains/create/domain-create.page').then(
            (m) => m.DomainCreatePageComponent,
          ),
      },
      {
        path: 'learning/concepts',
        loadComponent: () =>
          import('./admin/learning/concepts/list/concepts-list.page').then(
            (m) => m.ConceptsListPageComponent,
          ),
      },
      {
        path: 'learning/concepts/:slug',
        loadComponent: () =>
          import('./admin/learning/concepts/profile/concept-profile.page').then(
            (m) => m.ConceptProfilePageComponent,
          ),
      },
      {
        // A sessions LIST page does not exist yet (only the per-session
        // timeline below); placeholder keeps the nav entry resolvable.
        path: 'learning/sessions',
        pathMatch: 'full',
        loadComponent: () =>
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: { title: 'Sessions', crumbs: ['Learning', 'Sessions'] },
      },
      {
        path: 'learning/sessions/:id',
        loadComponent: () =>
          import('./admin/learning/sessions/timeline/session-timeline.page').then(
            (m) => m.SessionTimelinePageComponent,
          ),
      },
      {
        path: 'learning/plans',
        loadComponent: () =>
          import('./admin/learning/plans/list/plans-list.page').then(
            (m) => m.PlansListPageComponent,
          ),
      },
      {
        path: 'learning/plans/new',
        loadComponent: () =>
          import('./admin/learning/plans/create/plan-create.page').then(
            (m) => m.PlanCreatePageComponent,
          ),
      },
      {
        path: 'learning/plans/:id',
        loadComponent: () =>
          import('./admin/learning/plans/timeline/plan-timeline.page').then(
            (m) => m.PlanTimelinePageComponent,
          ),
      },
      {
        path: 'learning/hypotheses',
        loadComponent: () =>
          import('./admin/learning/hypotheses/list/hypotheses-list.page').then(
            (m) => m.HypothesesListPageComponent,
          ),
      },
      {
        path: 'learning/hypotheses/new',
        loadComponent: () =>
          import('./admin/learning/hypotheses/create/hypothesis-create.page').then(
            (m) => m.HypothesisCreatePageComponent,
          ),
      },
      {
        path: 'learning/hypotheses/:id',
        loadComponent: () =>
          import('./admin/learning/hypotheses/profile/hypothesis-profile.page').then(
            (m) => m.HypothesisProfilePageComponent,
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
