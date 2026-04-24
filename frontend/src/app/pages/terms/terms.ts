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
  standalone: true,
  templateUrl: './terms.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TermsComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Terms of Service',
      description: 'Terms of service for koopa0.dev — rules and conditions for using this website.',
      ogUrl: `${environment.siteUrl}/terms`,
    });
  }
}
