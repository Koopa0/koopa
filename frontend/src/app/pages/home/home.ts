import {
  Component,
  inject,
  ChangeDetectionStrategy,
  OnInit,
} from '@angular/core';
import { environment } from '../../../environments/environment';
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
    @defer (on viewport) {
      <app-featured-projects />
    } @placeholder {
      <div class="h-96 animate-pulse bg-zinc-900/50"></div>
    }
    @defer (on viewport) {
      <app-tech-stack />
    } @placeholder {
      <div class="h-64 animate-pulse bg-zinc-900/50"></div>
    }
    @defer (on viewport) {
      <app-latest-feed />
    } @placeholder {
      <div class="h-96 animate-pulse bg-zinc-900/50"></div>
    }
    @defer (on viewport) {
      <app-contact-cta />
    } @placeholder {
      <div class="h-48 animate-pulse bg-zinc-900/50"></div>
    }
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
        'Koopa — Software Engineer. Technical articles and personal projects.',
      ogUrl: `${environment.siteUrl}/`,
      jsonLd: buildWebSiteSchema(),
    });
  }
}
