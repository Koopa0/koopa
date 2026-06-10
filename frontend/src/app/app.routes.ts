import { Routes } from '@angular/router';
import { adminGuard } from './core/guards/auth.guard';
import { contentEditorCanDeactivate } from './admin/knowledge/content/editor/content-editor.guard';
import { noteEditorCanDeactivate } from './admin/knowledge/notes/editor/note-editor.guard';

export const routes: Routes = [
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
  },
  {
    path: 'essays',
    loadComponent: () =>
      import('./pages/essays/essays').then((m) => m.EssaysComponent),
  },
  {
    path: 'essays/:slug',
    loadComponent: () =>
      import('./pages/essay-detail/essay-detail').then(
        (m) => m.EssayDetailComponent,
      ),
  },
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
    path: 'til',
    loadComponent: () =>
      import('./pages/tils/tils').then((m) => m.TilsComponent),
  },
  {
    path: 'til/:slug',
    loadComponent: () =>
      import('./pages/til-detail/til-detail').then((m) => m.TilDetailComponent),
  },
  {
    path: 'search',
    loadComponent: () =>
      import('./pages/search/search').then((m) => m.SearchComponent),
  },
  {
    path: 'build-logs',
    loadComponent: () =>
      import('./pages/build-logs/build-logs').then((m) => m.BuildLogsComponent),
  },
  {
    path: 'build-logs/:slug',
    loadComponent: () =>
      import('./pages/build-log-detail/build-log-detail').then(
        (m) => m.BuildLogDetailComponent,
      ),
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
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: { title: 'Plan', crumbs: ['Daily', 'Plan'] },
      },
      {
        path: 'daily/todos',
        loadComponent: () =>
          import('./admin/commitment/todos/list/todos-list.page').then(
            (m) => m.TodosListPageComponent,
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
          import(
            './admin/commitment/projects/profile/project-profile.page'
          ).then((m) => m.ProjectProfilePageComponent),
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
        // The content editor hard-requires a content :id (rxResource
        // fetches on init); the create flow ships in a later batch.
        path: 'knowledge/content/new',
        loadComponent: () =>
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: {
          title: 'New content',
          crumbs: ['Knowledge', 'Content', 'New'],
        },
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
        // The note editor hard-requires a note :id (rxResource fetches
        // on init); the create flow ships in a later batch.
        path: 'knowledge/notes/new',
        loadComponent: () =>
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: { title: 'New note', crumbs: ['Knowledge', 'Notes', 'New'] },
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
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: { title: 'Search', crumbs: ['Knowledge', 'Search'] },
      },
      {
        path: 'knowledge/tags',
        loadComponent: () =>
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: {
          title: 'Tags & topics',
          crumbs: ['Knowledge', 'Tags & topics'],
        },
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
          import(
            './admin/learning/sessions/timeline/session-timeline.page'
          ).then((m) => m.SessionTimelinePageComponent),
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
          import(
            './admin/learning/hypotheses/create/hypothesis-create.page'
          ).then((m) => m.HypothesisCreatePageComponent),
      },
      {
        path: 'learning/hypotheses/:id',
        loadComponent: () =>
          import(
            './admin/learning/hypotheses/profile/hypothesis-profile.page'
          ).then((m) => m.HypothesisProfilePageComponent),
      },

      // ── System ───────────────────────────────────────────────────
      {
        path: 'system/health',
        loadComponent: () =>
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: { title: 'Health', crumbs: ['System', 'Health'] },
      },
      {
        path: 'system/stats',
        loadComponent: () =>
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: { title: 'Stats', crumbs: ['System', 'Stats'] },
      },
      {
        path: 'system/activity',
        loadComponent: () =>
          import('./admin/coordination/activity/activity.page').then(
            (m) => m.ActivityPageComponent,
          ),
      },
      {
        path: 'system/agents',
        loadComponent: () =>
          import('./admin/coordination/agents/list/agents-list.page').then(
            (m) => m.AgentsListPageComponent,
          ),
      },
      {
        path: 'system/agents/:name',
        loadComponent: () =>
          import('./admin/coordination/agents/profile/agent-profile.page').then(
            (m) => m.AgentProfilePageComponent,
          ),
      },

      // ── Settings ─────────────────────────────────────────────────
      {
        path: 'settings',
        loadComponent: () =>
          import('./admin/shared/admin-placeholder.component').then(
            (m) => m.AdminPlaceholderComponent,
          ),
        data: { title: 'Settings', crumbs: ['Settings'] },
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
