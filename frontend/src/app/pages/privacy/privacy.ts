import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-privacy',
  standalone: true,
  templateUrl: './privacy.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PrivacyComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Privacy Policy',
      description: 'Privacy policy for koopa0.dev — how we collect, use, and protect your information.',
      ogUrl: `${environment.siteUrl}/privacy`,
    });
  }
}
