import { mergeApplicationConfig, ApplicationConfig } from '@angular/core';
import { HTTP_TRANSFER_CACHE_ORIGIN_MAP } from '@angular/common/http';
import { provideServerRendering, withRoutes } from '@angular/ssr';
import { appConfig } from './app.config';
import { serverRoutes } from './app.routes.server';
import { environment } from '../environments/environment';

const serverConfig: ApplicationConfig = {
  providers: [
    provideServerRendering(withRoutes(serverRoutes)),
    // Maps the SSR API origin (ssrApiUrl) to the public browser origin (apiUrl)
    // so the HTTP transfer cache treats a request made during SSR and the same
    // request replayed on hydration as identical, letting the client reuse the
    // server's response instead of re-fetching. Without this the freshly
    // painted content flashes away and reloads on first paint. Server-only:
    // Angular errors if this token is present in the browser bundle.
    {
      provide: HTTP_TRANSFER_CACHE_ORIGIN_MAP,
      useValue: {
        [new URL(environment.ssrApiUrl).origin]: new URL(environment.apiUrl)
          .origin,
      },
    },
  ],
};

export const config = mergeApplicationConfig(appConfig, serverConfig);
