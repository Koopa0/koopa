import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

@Component({
  selector: 'app-terms',
  standalone: true,
  templateUrl: './terms.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class TermsComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: '服務條款',
      description: 'koopa0.dev 的服務條款，說明使用本網站的規範與條件。',
      ogUrl: 'https://koopa0.dev/terms',
    });
  }
}
