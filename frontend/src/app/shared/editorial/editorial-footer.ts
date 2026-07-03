import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';

/**
 * The public footer — a mono colophon line: the wordmark, a low-key link to the
 * hire/studio page, then the github and rss links and the copyright. The year is
 * a literal so the line is stable across SSR/CSR.
 */
@Component({
  selector: 'app-editorial-footer',
  imports: [RouterLink],
  templateUrl: './editorial-footer.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EditorialFooterComponent {
  protected readonly year = 2026;
}
