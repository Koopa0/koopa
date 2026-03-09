import { Routes } from '@angular/router';
import { authGuard, adminGuard } from './core/guards/auth.guard';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  {
    path: 'home',
    loadComponent: () =>
      import('./pages/home/home').then((m) => m.HomeComponent),
  },
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
    loadComponent: () =>
      import('./pages/resume/resume').then((m) => m.ResumeComponent),
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
    path: 'login',
    loadComponent: () =>
      import('./pages/login/login').then((m) => m.LoginComponent),
  },
  {
    path: 'admin',
    loadComponent: () =>
      import('./admin/dashboard/dashboard').then((m) => m.DashboardComponent),
    canActivate: [adminGuard],
  },
  {
    path: 'admin/editor',
    loadComponent: () =>
      import('./admin/article-editor/article-editor').then(
        (m) => m.ArticleEditorComponent,
      ),
    canActivate: [adminGuard],
  },
  {
    path: 'admin/editor/:id',
    loadComponent: () =>
      import('./admin/article-editor/article-editor').then(
        (m) => m.ArticleEditorComponent,
      ),
    canActivate: [adminGuard],
  },
  {
    path: 'admin/project-editor',
    loadComponent: () =>
      import('./admin/project-editor/project-editor').then(
        (m) => m.ProjectEditorComponent,
      ),
    canActivate: [adminGuard],
  },
  {
    path: 'admin/project-editor/:id',
    loadComponent: () =>
      import('./admin/project-editor/project-editor').then(
        (m) => m.ProjectEditorComponent,
      ),
    canActivate: [adminGuard],
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
