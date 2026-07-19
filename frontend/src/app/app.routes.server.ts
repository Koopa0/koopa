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
    path: 'articles/:slug',
    renderMode: RenderMode.Server,
  },
  {
    path: 'topics',
    renderMode: RenderMode.Server,
  },
  {
    path: 'topics/:slug',
    renderMode: RenderMode.Server,
  },
  {
    path: 'about',
    renderMode: RenderMode.Prerender,
  },
  {
    // Static single-owner studio page — prerendered like /about.
    path: 'hire',
    renderMode: RenderMode.Prerender,
  },
  {
    // Static single-owner legal text — prerendered like /about.
    path: 'privacy',
    renderMode: RenderMode.Prerender,
  },
  {
    // Static single-owner legal text — prerendered like /about.
    path: 'terms',
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
