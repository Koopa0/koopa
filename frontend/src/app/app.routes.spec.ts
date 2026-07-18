import { describe, expect, it } from 'vitest';
import { routes } from './app.routes';
import { serverRoutes } from './app.routes.server';
import { ADMIN_NAV } from './admin/admin-layout/admin-nav.config';

describe('public route retirement', () => {
  it('does not expose the retired public search page', () => {
    expect(routes.some((route) => route.path === 'search')).toBe(false);
    expect(serverRoutes.some((route) => route.path === 'search')).toBe(false);

    // Positive controls ensure the test inspected the real public route tables.
    expect(routes.some((route) => route.path === 'articles')).toBe(true);
    expect(serverRoutes.some((route) => route.path === 'articles')).toBe(true);
  });
});

describe('admin route retirement', () => {
  it('does not expose the retired dedicated content-search page', () => {
    const adminRoutes = routes.find((route) => route.path === 'admin')?.children;

    expect(
      adminRoutes?.some((route) => route.path === 'knowledge/search'),
    ).toBe(false);
    expect(
      adminRoutes?.some((route) => route.path === 'knowledge/content'),
    ).toBe(true);
  });

  it('does not advertise the retired search page in admin navigation', () => {
    const navRoutes = ADMIN_NAV.flatMap((group) =>
      group.items.map((item) => item.route),
    );

    expect(navRoutes).not.toContain('/admin/knowledge/search');
    expect(navRoutes).toContain('/admin/knowledge/content');
  });
});
