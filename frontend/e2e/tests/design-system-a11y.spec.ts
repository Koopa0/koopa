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
  test('showcase — dark theme (default)', async ({ page }) => {
    await page.goto('/design-system');
    await page.waitForLoadState('networkidle');
    const { violations } = await scan(page);
    const blockers = blocking(violations);
    expect(blockers, `serious/critical: ${summarize(blockers)}`).toEqual([]);
  });

  test('showcase — light theme', async ({ page }) => {
    await page.goto('/design-system');
    await page.waitForLoadState('networkidle');
    await page.evaluate(() =>
      document.documentElement.setAttribute('data-theme', 'light'),
    );
    const { violations } = await scan(page);
    const blockers = blocking(violations);
    expect(blockers, `serious/critical: ${summarize(blockers)}`).toEqual([]);
  });

  test('showcase — color-contrast clean in both themes', async ({ page }) => {
    await page.goto('/design-system');
    await page.waitForLoadState('networkidle');
    for (const theme of ['dark', 'light']) {
      await page.evaluate(
        (t) => document.documentElement.setAttribute('data-theme', t),
        theme,
      );
      const results = await new AxeBuilder({ page })
        .withRules(['color-contrast'])
        .analyze();
      expect(
        results.violations,
        `${theme}: ${summarize(results.violations)}`,
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
