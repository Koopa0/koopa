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
  templateUrl: './privacy.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PrivacyComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Privacy',
      description:
        'Privacy notes for koopa0.dev — a single-owner personal website. What is logged, what is not tracked.',
      ogUrl: `${environment.siteUrl}/privacy`,
    });
  }
}
