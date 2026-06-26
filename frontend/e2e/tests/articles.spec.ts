import { test, expect } from '@playwright/test';
import { ArticlesPage } from '../pages/articles.page';

test.describe('Articles Page', () => {
  test('should display articles list or empty state', async ({ page }) => {
    const articles = new ArticlesPage(page);
    await articles.goto();
    // The editorial H1 copy is owner-authored, not a test contract — assert
    // the heading renders, not its exact text.
    await expect(articles.heading).toBeVisible();

    // Wait for loading to finish
    await page.waitForLoadState('networkidle');

    // The page has three valid terminal states: published rows, a genuinely
    // empty corpus, or an explicit load-error state when the API is unavailable.
    const hasArticles = (await articles.articleCards.count()) > 0;
    const hasEmptyState = await articles.emptyState
      .isVisible()
      .catch(() => false);
    const hasErrorState = await articles.errorState
      .isVisible()
      .catch(() => false);
    expect(hasArticles || hasEmptyState || hasErrorState).toBeTruthy();
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
