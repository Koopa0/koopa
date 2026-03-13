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
    path: 'tags/:tag',
    loadComponent: () => import('./pages/tag/tag').then((m) => m.TagComponent),
  },
  {
    path: 'build-logs',
    loadComponent: () =>
      import('./pages/build-logs/build-logs').then(
        (m) => m.BuildLogsComponent,
      ),
  },
  {
    path: 'build-logs/:slug',
    loadComponent: () =>
      import('./pages/build-log-detail/build-log-detail').then(
        (m) => m.BuildLogDetailComponent,
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
      import('./pages/til-detail/til-detail').then(
        (m) => m.TilDetailComponent,
      ),
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
    path: 'resume',
    redirectTo: '/about',
    pathMatch: 'full',
  },
  {
    path: 'uses',
    loadComponent: () =>
      import('./pages/uses/uses').then((m) => m.UsesComponent),
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
    loadComponent: () =>
      import('./admin/oauth-callback/oauth-callback'),
  },
  {
    path: 'admin',
    loadComponent: () =>
      import('./admin/admin-layout/admin-layout').then(
        (m) => m.AdminLayoutComponent,
      ),
    canActivate: [adminGuard],
    children: [
      {
        path: '',
        loadComponent: () =>
          import('./admin/dashboard/dashboard').then(
            (m) => m.DashboardComponent,
          ),
      },
      {
        path: 'flow-runs',
        loadComponent: () =>
          import('./admin/flow-runs/flow-runs').then(
            (m) => m.FlowRunsComponent,
          ),
      },
      {
        path: 'feeds',
        loadComponent: () =>
          import('./admin/feeds/feeds').then((m) => m.FeedsComponent),
      },
      {
        path: 'collected',
        loadComponent: () =>
          import('./admin/collected/collected').then(
            (m) => m.CollectedComponent,
          ),
      },
      {
        path: 'review',
        loadComponent: () =>
          import('./admin/review/review').then((m) => m.ReviewComponent),
      },
      {
        path: 'editor',
        loadComponent: () =>
          import('./admin/article-editor/article-editor').then(
            (m) => m.ArticleEditorComponent,
          ),
        canDeactivate: [unsavedChangesGuard],
      },
      {
        path: 'editor/:id',
        loadComponent: () =>
          import('./admin/article-editor/article-editor').then(
            (m) => m.ArticleEditorComponent,
          ),
        canDeactivate: [unsavedChangesGuard],
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
      import('./pages/error/error.component').then(
        (m) => m.ErrorComponent,
      ),
  },
  {
    path: '**',
    loadComponent: () =>
      import('./pages/not-found/not-found.component').then(
        (m) => m.NotFoundComponent,
      ),
  },
];
