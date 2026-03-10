import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import {
  LucideAngularModule,
  Mail,
  Github,
  Linkedin,
} from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildPersonSchema } from '../../core/services/seo/json-ld.util';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

@Component({
  selector: 'app-about',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './about.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class AboutComponent implements OnInit {
  private readonly seoService = inject(SeoService);
  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'About',
      description: 'Koopa — Software Engineer. Go, Angular, and cloud-native technologies.',
      ogUrl: 'https://koopa0.dev/about',
      ogType: 'profile',
      jsonLd: buildPersonSchema(),
    });
  }

  protected readonly MailIcon = Mail;
  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
}
