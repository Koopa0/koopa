import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';

/**
 * Work with me — the studio page. A centered editorial reading column (the same
 * .ed-prose article-body treatment /about and the article pages use, with the
 * one kintsugi seam) carrying the studio positioning, the two work lines,
 * receipts, and the contact channels. It reads at the weight of a written piece,
 * like /about — deliberately not the plain legal-page style of /privacy.
 */
@Component({
  selector: 'app-hire',
  imports: [RouterLink],
  templateUrl: './hire.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HireComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Work with me',
      description:
        'Koopa — a one-person studio building and delivering Go backend and agent systems to a strict engineering bar, remotely, with teams anywhere.',
      ogUrl: `${environment.siteUrl}/hire`,
    });
  }
}
