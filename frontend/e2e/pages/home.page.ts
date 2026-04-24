import type { Page, Locator } from '@playwright/test';

export class HomePage {
  readonly heading: Locator;
  readonly heroSection: Locator;
  readonly latestArticles: Locator;
  readonly navLinks: Locator;

  constructor(private readonly page: Page) {
    this.heading = page.locator('h1').first();
    this.heroSection = page.locator('section').first();
    this.latestArticles = page.locator('text=Latest');
    this.navLinks = page.locator('nav a');
  }

  async goto() {
    await this.page.goto('/');
  }
}
