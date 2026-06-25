import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, ArrowRight } from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildWebSiteSchema } from '../../core/services/seo/json-ld.util';
import { PostRowComponent } from '../../shared/post-row/post-row.component';
import type { ApiContent, ApiListResponse } from '../../core/models';

const RECENT_LIMIT = 5;

/**
 * The public front door (route `''`). A person-forward intro — positioning
 * statement, short bio, social links — then the most recent writing as cards.
 *
 * The recent list is wrapped in `@defer (hydrate on idle)` so the server-rendered
 * cards stay painted straight through hydration: no loading skeleton, no
 * content flash. The full reading wall lives at `/articles`.
 */
@Component({
  selector: 'app-home',
  imports: [RouterLink, LucideAngularModule, PostRowComponent],
  templateUrl: './home.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HomeComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly seoService = inject(SeoService);

  protected readonly ArrowRightIcon = ArrowRight;

  protected readonly contentsResource = rxResource<
    ApiListResponse<ApiContent>,
    void
  >({
    stream: () =>
      this.contentService.listPublished({ page: 1, perPage: RECENT_LIMIT }),
  });

  private readonly contents = computed(() =>
    this.contentsResource.hasValue() ? this.contentsResource.value().data : [],
  );

  /** The newest published pieces across every type. */
  protected readonly recent = computed(() =>
    this.contents().slice(0, RECENT_LIMIT),
  );

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'koopa0.dev',
      description: 'Notes, systems, and what I am working out.',
      ogUrl: environment.siteUrl,
      canonicalUrl: environment.siteUrl,
      jsonLd: buildWebSiteSchema(),
    });
  }
}
