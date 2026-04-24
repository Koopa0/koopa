import type { Page, Locator } from '@playwright/test';

export class ArticlesPage {
  readonly heading: Locator;
  readonly articleCards: Locator;
  readonly searchInput: Locator;
  readonly loadingIndicator: Locator;

  constructor(private readonly page: Page) {
    this.heading = page.locator('h1');
    this.articleCards = page.locator('a[href^="/articles/"]');
    this.searchInput = page.locator('input[type="search"], input[placeholder*="Search"]');
    this.loadingIndicator = page.locator('.animate-pulse');
  }

  async goto() {
    await this.page.goto('/articles');
  }
}
