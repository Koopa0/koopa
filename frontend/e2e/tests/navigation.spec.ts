import { test, expect } from '@playwright/test';
import { HomePage } from '../pages/home.page';

test.describe('Site Navigation', () => {
  test('should load home page', async ({ page }) => {
    const home = new HomePage(page);
    await home.goto();
    await expect(home.heading).toBeVisible();
    await expect(page).toHaveTitle(/koopa0\.dev|Koopa/i);
  });

  test('should navigate to articles page', async ({ page }) => {
    await page.goto('/');
    await page.click('a[href="/articles"]');
    await expect(page).toHaveURL(/\/articles/);
    // Assert the index heading renders rather than a specific marketing
    // copy string — the editorial H1 ("Everything I've written down.") is
    // owner-authored copy, not a stable test contract.
    await expect(page.locator('h1')).toBeVisible();
  });

  // /build-logs and /til standalone routes are permanently retired: every
  // content type (article/essay/build-log/til/digest) is consolidated into the
  // /articles index, narrowed by the optional ?type= query param. Both paths
  // now resolve to the 404 route, asserted below.
  test('should 404 for retired standalone content routes', async ({ page }) => {
    for (const path of ['/build-logs', '/til']) {
      await page.goto(path);
      await expect(page.locator('body')).toContainText(/not found|404/i);
    }
  });

  test('should show 404 for unknown routes', async ({ page }) => {
    await page.goto('/nonexistent-page-xyz');
    await expect(page.locator('body')).toContainText(/not found|404/i);
  });
});
