import {
  Component,
  inject,
  ChangeDetectionStrategy,
  OnInit,
} from '@angular/core';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { buildWebSiteSchema } from '../../core/services/seo/json-ld.util';
import { HeroSectionComponent } from './sections/hero-section.component';
import { FeaturedProjectsComponent } from './sections/featured-projects.component';
import { TechStackComponent } from './sections/tech-stack.component';
import { LatestFeedComponent } from './sections/latest-feed.component';
import { ContactCtaComponent } from './sections/contact-cta.component';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [
    HeroSectionComponent,
    FeaturedProjectsComponent,
    TechStackComponent,
    LatestFeedComponent,
    ContactCtaComponent,
  ],
  template: `
    <app-hero-section />
    <app-featured-projects />
    <app-tech-stack />
    <app-latest-feed />
    <app-contact-cta />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class HomeComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Home',
      description:
        'Koopa — Backend Engineer / Full-Stack Developer. Technical articles and personal projects.',
      ogUrl: 'https://koopa0.dev/home',
      jsonLd: buildWebSiteSchema(),
    });
  }
}
