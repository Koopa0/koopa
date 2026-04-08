import { Routes } from '@angular/router';
import { adminGuard } from './core/guards/auth.guard';
import { unsavedChangesGuard } from './core/guards/unsaved-changes.guard';

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
      // — 預設導向 Today —
      {
        path: '',
        redirectTo: 'today',
        pathMatch: 'full',
      },
      {
        path: 'today',
        loadComponent: () =>
          import('./admin/today/today').then((m) => m.TodayComponent),
      },

      // — Inbox —
      {
        path: 'inbox',
        loadComponent: () =>
          import('./admin/inbox/inbox').then((m) => m.InboxComponent),
      },

      // — Plan —
      {
        path: 'plan',
        redirectTo: 'plan/goals',
        pathMatch: 'full',
      },
      {
        path: 'plan/goals',
        loadComponent: () =>
          import('./admin/goals/goals').then((m) => m.GoalsComponent),
      },
      {
        path: 'plan/goals/:id',
        loadComponent: () =>
          import('./admin/goals/goal-detail').then(
            (m) => m.GoalDetailComponent,
          ),
      },
      {
        path: 'plan/projects',
        loadComponent: () =>
          import('./admin/projects/projects').then(
            (m) => m.AdminProjectsComponent,
          ),
      },
      {
        path: 'plan/projects/:id',
        loadComponent: () =>
          import('./admin/projects/project-detail').then(
            (m) => m.ProjectDetailComponent,
          ),
      },
      {
        path: 'plan/tasks',
        loadComponent: () =>
          import('./admin/tasks/tasks').then((m) => m.TasksComponent),
      },

      // — Library —
      {
        path: 'library',
        redirectTo: 'library/pipeline',
        pathMatch: 'full',
      },
      {
        path: 'library/pipeline',
        loadComponent: () =>
          import('./admin/library/library-pipeline').then(
            (m) => m.LibraryPipelineComponent,
          ),
      },
      {
        path: 'library/contents',
        loadComponent: () =>
          import('./admin/contents/contents').then(
            (m) => m.AdminContentsComponent,
          ),
      },
      {
        path: 'library/editor',
        loadComponent: () =>
          import('./admin/article-editor/article-editor').then(
            (m) => m.ArticleEditorComponent,
          ),
        canDeactivate: [unsavedChangesGuard],
      },
      {
        path: 'library/editor/:id',
        loadComponent: () =>
          import('./admin/article-editor/article-editor').then(
            (m) => m.ArticleEditorComponent,
          ),
        canDeactivate: [unsavedChangesGuard],
      },

      // — System（現有頁面暫放此區）—
      {
        path: 'system/feeds',
        loadComponent: () =>
          import('./admin/feeds/feeds').then((m) => m.FeedsComponent),
      },
      {
        path: 'system/tags',
        loadComponent: () =>
          import('./admin/tags/tags').then((m) => m.TagsComponent),
      },
      {
        path: 'system/activity',
        loadComponent: () =>
          import('./admin/activity/activity').then((m) => m.ActivityComponent),
      },

      // — Legacy redirects（避免舊書籤失效）—
      { path: 'dashboard', redirectTo: 'today', pathMatch: 'full' },
      { path: 'contents', redirectTo: 'library/contents', pathMatch: 'full' },
      { path: 'feeds', redirectTo: 'system/feeds', pathMatch: 'full' },
      { path: 'tags', redirectTo: 'system/tags', pathMatch: 'full' },
      { path: 'activity', redirectTo: 'system/activity', pathMatch: 'full' },
      { path: 'projects', redirectTo: 'plan/projects', pathMatch: 'full' },
      { path: 'goals', redirectTo: 'plan/goals', pathMatch: 'full' },
      { path: 'editor', redirectTo: 'library/editor', pathMatch: 'full' },
      {
        path: 'editor/:id',
        redirectTo: 'library/editor/:id',
        pathMatch: 'full',
      },
      {
        path: 'project-editor',
        loadComponent: () =>
          import('./admin/project-editor/project-editor').then(
            (m) => m.ProjectEditorComponent,
          ),
        canDeactivate: [unsavedChangesGuard],
      },
      {
        path: 'project-editor/:id',
        loadComponent: () =>
          import('./admin/project-editor/project-editor').then(
            (m) => m.ProjectEditorComponent,
          ),
        canDeactivate: [unsavedChangesGuard],
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
