import { RenderMode, ServerRoute } from '@angular/ssr';

export const serverRoutes: ServerRoute[] = [
  {
    path: '',
    renderMode: RenderMode.Server,
  },
  {
    path: 'articles',
    renderMode: RenderMode.Server,
  },
  {
    path: 'articles/:id',
    renderMode: RenderMode.Server,
  },
  {
    path: 'projects',
    renderMode: RenderMode.Server,
  },
  {
    path: 'projects/:slug',
    renderMode: RenderMode.Server,
  },
  {
    path: 'tags/:tag',
    renderMode: RenderMode.Server,
  },
  {
    path: 'build-logs',
    renderMode: RenderMode.Server,
  },
  {
    path: 'build-logs/:slug',
    renderMode: RenderMode.Server,
  },
  {
    path: 'til',
    renderMode: RenderMode.Server,
  },
  {
    path: 'til/:slug',
    renderMode: RenderMode.Server,
  },
  {
    path: 'notes',
    renderMode: RenderMode.Server,
  },
  {
    path: 'notes/:slug',
    renderMode: RenderMode.Server,
  },
  {
    path: 'uses',
    renderMode: RenderMode.Prerender,
  },
  {
    path: 'about',
    renderMode: RenderMode.Prerender,
  },
  {
    path: 'login',
    renderMode: RenderMode.Client,
  },
  {
    path: 'error',
    renderMode: RenderMode.Client,
  },
  {
    path: 'admin/oauth-callback',
    renderMode: RenderMode.Client,
  },
  {
    path: 'admin',
    renderMode: RenderMode.Client,
  },
  {
    path: 'admin/**',
    renderMode: RenderMode.Client,
  },
  {
    path: '**',
    renderMode: RenderMode.Server,
  },
];
