import { Routes } from '@angular/router';
import { adminGuard } from './core/guards/auth.guard';

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
    path: 'articles/:id',
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
    path: 'essays/:id',
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
    path: 'tags/:tag',
    loadComponent: () => import('./pages/tag/tag').then((m) => m.TagComponent),
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
    path: 'notes',
    loadComponent: () =>
      import('./pages/notes/notes').then((m) => m.NotesComponent),
  },
  {
    path: 'notes/:slug',
    loadComponent: () =>
      import('./pages/note-detail/note-detail').then(
        (m) => m.NoteDetailComponent,
      ),
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
    path: 'bookmarks',
    loadComponent: () =>
      import('./pages/bookmarks/bookmarks').then((m) => m.BookmarksComponent),
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
      { path: '', redirectTo: 'overview', pathMatch: 'full' },
      {
        path: 'overview',
        loadComponent: () =>
          import('./admin/overview/overview').then((m) => m.OverviewComponent),
      },

      // — Learn —
      { path: 'learn', redirectTo: 'learn/weaknesses', pathMatch: 'full' },
      {
        path: 'learn/weaknesses',
        loadComponent: () =>
          import('./admin/learn/weakness-map').then(
            (m) => m.WeaknessMapComponent,
          ),
      },
      {
        path: 'learn/concepts/:slug',
        loadComponent: () =>
          import('./admin/learn/concept-drilldown').then(
            (m) => m.ConceptDrilldownComponent,
          ),
      },
      {
        path: 'learn/sessions',
        loadComponent: () =>
          import('./admin/learn/session-history').then(
            (m) => m.SessionHistoryComponent,
          ),
      },
      {
        path: 'learn/plans',
        loadComponent: () =>
          import('./admin/learn/plans-list').then((m) => m.PlansListComponent),
      },
      {
        path: 'learn/plans/:id',
        loadComponent: () =>
          import('./admin/learn/plan-detail').then(
            (m) => m.PlanDetailComponent,
          ),
      },

      // — Content —
      { path: 'content', redirectTo: 'content/pipeline', pathMatch: 'full' },
      {
        path: 'content/pipeline',
        loadComponent: () =>
          import('./admin/content/pipeline').then((m) => m.PipelineComponent),
      },
      {
        path: 'content/review/:id',
        loadComponent: () =>
          import('./admin/content/review').then((m) => m.ReviewComponent),
      },
      {
        path: 'content/library',
        loadComponent: () =>
          import('./admin/content/library').then((m) => m.LibraryComponent),
      },
      {
        path: 'content/intelligence',
        loadComponent: () =>
          import('./admin/content/intelligence').then(
            (m) => m.IntelligenceComponent,
          ),
      },
      {
        path: 'content/collected',
        loadComponent: () =>
          import('./admin/content/collected').then((m) => m.CollectedComponent),
      },

      // — Commitments —
      {
        path: 'commitments',
        redirectTo: 'commitments/goals',
        pathMatch: 'full',
      },
      {
        path: 'commitments/goals',
        loadComponent: () =>
          import('./admin/commitments/goals').then((m) => m.GoalsComponent),
      },
      {
        path: 'commitments/projects',
        loadComponent: () =>
          import('./admin/commitments/projects').then(
            (m) => m.ProjectsComponent,
          ),
      },
      {
        path: 'commitments/directives',
        loadComponent: () =>
          import('./admin/commitments/directives').then(
            (m) => m.DirectivesComponent,
          ),
      },

      // — Activity —
      { path: 'activity', redirectTo: 'activity/daily', pathMatch: 'full' },
      {
        path: 'activity/daily',
        loadComponent: () =>
          import('./admin/activity/daily-review').then(
            (m) => m.DailyReviewComponent,
          ),
      },
      {
        path: 'activity/weekly',
        loadComponent: () =>
          import('./admin/activity/weekly-review').then(
            (m) => m.WeeklyReviewComponent,
          ),
      },
      {
        path: 'activity/insights',
        loadComponent: () =>
          import('./admin/activity/insights').then((m) => m.InsightsComponent),
      },
      {
        path: 'activity/journal',
        loadComponent: () =>
          import('./admin/activity/journal').then((m) => m.JournalComponent),
      },

      // — System —
      {
        path: 'system',
        loadComponent: () =>
          import('./admin/system/system-health').then(
            (m) => m.SystemHealthComponent,
          ),
      },
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
