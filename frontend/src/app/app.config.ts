import {
  ApplicationConfig,
  provideBrowserGlobalErrorListeners,
  provideZoneChangeDetection,
} from '@angular/core';
import {
  provideRouter,
  withComponentInputBinding,
  withInMemoryScrolling,
  withViewTransitions,
} from '@angular/router';
import {
  provideClientHydration,
  withEventReplay,
} from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import {
  provideHttpClient,
  withFetch,
  withInterceptors,
} from '@angular/common/http';

import { routes } from './app.routes';
import { authInterceptor } from './core/interceptors/auth.interceptor';
import { errorInterceptor } from './core/interceptors/error.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZoneChangeDetection({ eventCoalescing: true }),
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
    provideHttpClient(
      withFetch(),
      withInterceptors([authInterceptor, errorInterceptor]),
    ),
    provideClientHydration(withEventReplay()),
  ],
};
