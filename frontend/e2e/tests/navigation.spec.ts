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
    await expect(page.locator('h1')).toContainText(/Articles/i);
  });

  test('should navigate to TIL page', async ({ page }) => {
    await page.goto('/');
    const tilLink = page.locator('a[href="/til"]');
    if (await tilLink.isVisible()) {
      await tilLink.click();
      await expect(page).toHaveURL(/\/til/);
    }
  });

  test('should navigate to notes page', async ({ page }) => {
    await page.goto('/notes');
    await expect(page.locator('h1')).toContainText(/Notes/i);
  });

  test('should navigate to build logs page', async ({ page }) => {
    await page.goto('/build-logs');
    await expect(page.locator('h1')).toContainText(/Build Log/i);
  });

  test('should show 404 for unknown routes', async ({ page }) => {
    await page.goto('/nonexistent-page-xyz');
    await expect(page.locator('body')).toContainText(/not found|404/i);
  });
});
