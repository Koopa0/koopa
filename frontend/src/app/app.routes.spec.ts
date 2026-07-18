import { describe, expect, it } from 'vitest';
import { routes } from './app.routes';
import { serverRoutes } from './app.routes.server';

describe('public route retirement', () => {
  it('does not expose the retired public search page', () => {
    expect(routes.some((route) => route.path === 'search')).toBe(false);
    expect(serverRoutes.some((route) => route.path === 'search')).toBe(false);

    // Positive controls ensure the test inspected the real public route tables.
    expect(routes.some((route) => route.path === 'articles')).toBe(true);
    expect(serverRoutes.some((route) => route.path === 'articles')).toBe(true);
  });
});
