import type { Page, Locator } from '@playwright/test';

export class ArticlesPage {
  readonly heading: Locator;
  readonly articleCards: Locator;
  readonly emptyState: Locator;
  readonly errorState: Locator;
  readonly searchInput: Locator;
  readonly loadingIndicator: Locator;

  constructor(private readonly page: Page) {
    this.heading = page.locator('h1');
    this.articleCards = page.locator('a[href^="/articles/"]');
    this.emptyState = page.getByTestId('articles-empty');
    this.errorState = page.getByTestId('articles-error');
    this.searchInput = page.locator('input[type="search"], input[placeholder*="Search"]');
    this.loadingIndicator = page.locator('.animate-pulse');
  }

  async goto() {
    await this.page.goto('/articles');
  }
}
