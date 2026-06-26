import { inject } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { ResolveFn, RedirectCommand, Router } from '@angular/router';
import { catchError, of } from 'rxjs';
import { ArticleService } from '../../core/services/article.service';
import type { ApiContent } from '../../core/models';

/**
 * Resolves the article before the route activates so the page-level view
 * transition lands on the fully-rendered reading surface instead of the
 * loading spinner. Running on the server (RenderMode.Server) populates the
 * transfer cache, so the client never refetches on hydration.
 *
 * A missing or unpublished slug (404) routes to the not-found page; any other
 * failure (network / 5xx) routes to the error page.
 */
export const articleResolver: ResolveFn<ApiContent> = (route) => {
  const slug = route.paramMap.get('slug') ?? '';
  const articles = inject(ArticleService);
  const router = inject(Router);

  return articles.getArticleBySlug(slug).pipe(
    catchError((err: unknown) => {
      const notFound = err instanceof HttpErrorResponse && err.status === 404;
      return of(
        new RedirectCommand(
          router.parseUrl(notFound ? '/not-found' : '/error'),
        ),
      );
    }),
  );
};
