import {
  ApplicationConfig,
  provideBrowserGlobalErrorListeners,
  provideZonelessChangeDetection,
} from '@angular/core';
import {
  provideRouter,
  withComponentInputBinding,
  withInMemoryScrolling,
  withViewTransitions,
} from '@angular/router';
import {
  provideClientHydration,
  withHttpTransferCacheOptions,
} from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideHttpClient, withInterceptors } from '@angular/common/http';

import { routes } from './app.routes';
import { authInterceptor } from './core/interceptors/auth.interceptor';
import { errorInterceptor } from './core/interceptors/error.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZonelessChangeDetection(),
    provideRouter(
      routes,
      withComponentInputBinding(),
      withInMemoryScrolling({
        scrollPositionRestoration: 'top',
        anchorScrolling: 'enabled',
      }),
      withViewTransitions({
        skipInitialTransition: true,
        onViewTransitionCreated: ({ transition, from, to }) => {
          const fullPath = (route: import('@angular/router').ActivatedRouteSnapshot): string => {
            const parts: string[] = [];
            let cur: import('@angular/router').ActivatedRouteSnapshot | null = route;
            while (cur) {
              parts.unshift(...cur.url.map((s) => s.path));
              cur = cur.parent;
            }
            return '/' + parts.join('/');
          };
          const isAdminNav =
            fullPath(from).startsWith('/admin') &&
            fullPath(to).startsWith('/admin');
          if (isAdminNav) {
            transition.skipTransition();
          }
        },
      }),
    ),
    provideAnimationsAsync(),
    provideHttpClient(withInterceptors([authInterceptor, errorInterceptor])),
    // Incremental hydration is the v22 default and enables event replay
    // automatically; @defer blocks opt into lazy hydration via hydrate triggers.
    // withHttpTransferCacheOptions() serializes server-fetched GET/HEAD responses
    // into the hydration payload so the client reuses them instead of re-fetching
    // on hydration. The transfer cache is on by default; this states it explicitly.
    provideClientHydration(withHttpTransferCacheOptions({})),
  ],
};
