import {
  Component,
  inject,
  ChangeDetectionStrategy,
  OnInit,
  afterNextRender,
} from '@angular/core';
import { environment } from '../../../environments/environment';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildWebSiteSchema } from '../../core/services/seo/json-ld.util';
import { SmoothScrollService } from '../../core/services/smooth-scroll.service';
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
})
export class HomeComponent implements OnInit {
  private readonly seoService = inject(SeoService);
  private readonly smoothScroll = inject(SmoothScrollService);

  constructor() {
    afterNextRender(() => {
      this.smoothScroll.init();
    });
  }

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Home',
      description:
        'Koopa — Software Engineer. Technical articles and personal projects.',
      ogUrl: `${environment.siteUrl}/`,
      jsonLd: buildWebSiteSchema(),
    });
  }
}
