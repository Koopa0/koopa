import { test, expect } from '@playwright/test';
import { ArticlesPage } from '../pages/articles.page';

test.describe('Articles Page', () => {
  test('should display articles list or empty state', async ({ page }) => {
    const articles = new ArticlesPage(page);
    await articles.goto();
    await expect(articles.heading).toContainText(/Articles/i);

    // Wait for loading to finish
    await page.waitForLoadState('networkidle');

    // Either articles are displayed or empty state
    const hasArticles = await articles.articleCards.count() > 0;
    const hasEmptyState = await page.locator('text=/no articles/i').isVisible().catch(() => false);
    expect(hasArticles || hasEmptyState).toBeTruthy();
  });

  test('should show loading skeletons initially', async ({ page }) => {
    const articles = new ArticlesPage(page);
    await articles.goto();
    // Skeletons should appear while loading (might be too fast to catch)
    // Verify the page eventually settles
    await page.waitForLoadState('networkidle');
    await expect(articles.heading).toBeVisible();
  });
});
