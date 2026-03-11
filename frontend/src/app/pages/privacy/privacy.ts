import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

@Component({
  selector: 'app-privacy',
  standalone: true,
  templateUrl: './privacy.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class PrivacyComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: '隱私權政策',
      description: 'koopa0.dev 的隱私權政策，說明我們如何收集、使用和保護您的資訊。',
      ogUrl: 'https://koopa0.dev/privacy',
    });
  }
}
