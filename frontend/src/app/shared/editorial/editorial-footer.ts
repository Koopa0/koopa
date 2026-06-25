import { Component, ChangeDetectionStrategy } from '@angular/core';

/**
 * The public footer — a mono colophon line. "the published tip of a larger
 * system" states the relationship between the site and the knowledge engine
 * behind it (fact, not mood), then the github and rss links and the
 * copyright. The year is a literal so the line is stable across SSR/CSR.
 */
@Component({
  selector: 'app-editorial-footer',
  templateUrl: './editorial-footer.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EditorialFooterComponent {
  protected readonly year = 2026;
}
