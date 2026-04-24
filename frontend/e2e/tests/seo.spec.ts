import { test, expect } from '@playwright/test';

test.describe('SEO', () => {
  test('home page should have proper meta tags', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const title = await page.title();
    expect(title).toBeTruthy();

    const ogTitle = await page.getAttribute('meta[property="og:title"]', 'content');
    expect(ogTitle).toBeTruthy();

    const description = await page.getAttribute('meta[name="description"]', 'content');
    expect(description).toBeTruthy();
  });

  test('articles page should have meta tags', async ({ page }) => {
    await page.goto('/articles');
    await page.waitForLoadState('networkidle');

    const ogUrl = await page.getAttribute('meta[property="og:url"]', 'content');
    expect(ogUrl).toContain('/articles');
  });
});
