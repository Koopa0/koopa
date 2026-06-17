import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-terms',
  templateUrl: './terms.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TermsComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Terms',
      description:
        'Use, citation, and attribution notes for koopa0.dev — a single-owner personal website.',
      ogUrl: `${environment.siteUrl}/terms`,
    });
  }
}
