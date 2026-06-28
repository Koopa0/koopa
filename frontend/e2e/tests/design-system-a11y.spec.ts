import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * Accessibility gate for the DS component library (ingested from the Claude
 * Design "koopa.dev Design System"). Scans the /design-system showcase — which
 * renders every primitive in its variants — plus the public home page, in both
 * themes. Fails on any serious/critical WCAG 2 A/AA violation.
 */

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function scan(page: Page) {
  return new AxeBuilder({ page }).withTags(WCAG).analyze();
}

function blocking(violations: Awaited<ReturnType<typeof scan>>['violations']) {
  return violations.filter(
    (v) => v.impact === 'serious' || v.impact === 'critical',
  );
}

function summarize(violations: Awaited<ReturnType<typeof scan>>['violations']) {
  return violations
    .map((v) => `${v.id} (${v.impact}) ×${v.nodes.length}`)
    .join('; ');
}

test.describe('Design system a11y (WCAG AA)', () => {
  test('showcase — paper theme (default)', async ({ page }) => {
    await page.goto('/design-system');
    await page.waitForLoadState('networkidle');
    const { violations } = await scan(page);
    const blockers = blocking(violations);
    expect(blockers, `serious/critical: ${summarize(blockers)}`).toEqual([]);
  });

  test('showcase — dark twin', async ({ page }) => {
    await page.goto('/design-system');
    await page.waitForLoadState('networkidle');
    // The public dark twin is the `public-dark` class on <html>.
    await page.evaluate(() =>
      document.documentElement.classList.add('public-dark'),
    );
    const { violations } = await scan(page);
    const blockers = blocking(violations);
    expect(blockers, `serious/critical: ${summarize(blockers)}`).toEqual([]);
  });

  test('showcase — color-contrast clean in both themes', async ({ page }) => {
    await page.goto('/design-system');
    await page.waitForLoadState('networkidle');
    for (const dark of [false, true]) {
      await page.evaluate(
        (isDark) =>
          document.documentElement.classList.toggle('public-dark', isDark),
        dark,
      );
      const results = await new AxeBuilder({ page })
        .withRules(['color-contrast'])
        .analyze();
      expect(
        results.violations,
        `${dark ? 'dark' : 'paper'}: ${summarize(results.violations)}`,
      ).toEqual([]);
    }
  });

  test('home page — no serious/critical violations', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const { violations } = await scan(page);
    const blockers = blocking(violations);
    expect(blockers, `serious/critical: ${summarize(blockers)}`).toEqual([]);
  });
});
