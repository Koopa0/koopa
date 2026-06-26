import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildWebSiteSchema } from '../../core/services/seo/json-ld.util';
import type { ApiContent, ApiListResponse } from '../../core/models';

const RECENT_LIMIT = 5;

/** The cover's stance — the owner's existing line (a slot he may refine). */
const STATEMENT = "Notes, systems, and what I'm working out.";

/**
 * The public front door (route `''`) — a curated COVER, not a feed. One
 * featured lead (the newest piece, given serif weight) over a quiet hand of
 * recent titles and two signposts. The full reading wall lives at `/articles`;
 * Home deliberately renders no `app-post-row` so it cannot be mistaken for the
 * index. The lead and recent band render in the normal SSR pass — the server
 * resolves the content request and the HTTP transfer cache (see app.config)
 * hands it to the client, so the content is painted at first paint and settles
 * in with one calm fade rather than popping in after hydration.
 */
@Component({
  selector: 'app-home',
  imports: [RouterLink, DatePipe],
  templateUrl: './home.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HomeComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly seoService = inject(SeoService);

  protected readonly statement = STATEMENT;

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

  /** Still fetching — used to hold back the empty line until we truly know. */
  protected readonly loading = computed(
    () => this.contentsResource.status() === 'loading',
  );

  /** The single featured piece — newest published, the cover's pick. */
  protected readonly lead = computed(() => this.contents().at(0) ?? null);

  /** The next few, after the lead. */
  protected readonly more = computed(() =>
    this.contents().slice(1, RECENT_LIMIT),
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
