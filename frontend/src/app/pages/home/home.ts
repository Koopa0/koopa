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
import { LucideAngularModule, AlertTriangle, RefreshCw } from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { TopicService } from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildWebSiteSchema } from '../../core/services/seo/json-ld.util';
import type {
  ApiContent,
  ApiListResponse,
  ApiTopic,
} from '../../core/models';

const RECENT_LIMIT = 5;

/** The cover's stance — the owner's existing line (a slot he may refine). */
const STATEMENT = "Notes, systems, and what I'm working out.";

/** Cover topic index — cap, and the cold-start floors below which it would lie. */
const TOPIC_CAP = 9;
const MIN_TOPICS = 3;
const MIN_PIECES = 6;

/**
 * The public front door (route `''`) — a broadsheet COVER, not a feed. A wide,
 * left-anchored asymmetric grid whose oversized serif STATEMENT is the cover's
 * "image" (no photography); the Lead and a quiet recent strip sit in the major
 * column, a mono machine-voice frame (edition line) and a topic index in the
 * minor. Opening an article steps DOWN in scale and re-centres into the reading
 * column — the differentiation is the type-scale step-down + scan-vs-read
 * grammar, which survives the mobile stack where the asymmetry collapses.
 *
 * The lead/recent band render in the normal SSR pass — the server resolves the
 * content request and the HTTP transfer cache hands it to the client, so the
 * cover is painted at first paint.
 */
@Component({
  selector: 'app-home',
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './home.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HomeComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly topicService = inject(TopicService);
  private readonly seoService = inject(SeoService);

  protected readonly statement = STATEMENT;

  protected readonly AlertIcon = AlertTriangle;
  protected readonly RetryIcon = RefreshCw;

  protected readonly contentsResource = rxResource<
    ApiListResponse<ApiContent>,
    void
  >({
    stream: () =>
      this.contentService.listPublished({ page: 1, perPage: RECENT_LIMIT }),
  });

  protected readonly topicsResource = rxResource<ApiTopic[], void>({
    stream: () => this.topicService.getAllTopics(),
  });

  private readonly contents = computed(() =>
    this.contentsResource.hasValue() ? this.contentsResource.value().data : [],
  );

  /** Still fetching — used to hold back the empty line until we truly know. */
  protected readonly loading = computed(
    () => this.contentsResource.status() === 'loading',
  );

  /** Distinguishes a failed contents load from a genuinely empty corpus. */
  protected readonly loadError = computed(
    () => this.contentsResource.status() === 'error',
  );

  /** The single featured piece — newest published, the cover's pick. */
  protected readonly lead = computed(() => this.contents().at(0) ?? null);

  /** The next few, after the lead. */
  protected readonly more = computed(() =>
    this.contents().slice(1, RECENT_LIMIT),
  );

  /** Total published pieces — the edition count and the cold-start floor. */
  protected readonly pieceCount = computed(() =>
    this.contentsResource.hasValue()
      ? this.contentsResource.value().meta.total
      : 0,
  );

  /** Show the piece count only once it reads as a corpus, not a lie. */
  protected readonly showCount = computed(() => this.pieceCount() >= MIN_PIECES);

  /** Cover topic index — non-empty topics, in curated order, capped. */
  protected readonly coverTopics = computed(() =>
    this.topicsResource.hasValue()
      ? this.topicsResource
          .value()
          .filter((t) => t.content_count > 0)
          .sort((a, b) => a.sort_order - b.sort_order)
          .slice(0, TOPIC_CAP)
      : [],
  );

  /**
   * Cold-start guard: a topic index with counts only reads as a living system
   * once the corpus is non-trivial. Below the floor the counts would lie
   * ("0 · 1"), so the cover leans on the statement + lead + recent strip alone.
   */
  protected readonly showTopicIndex = computed(
    () =>
      this.coverTopics().length >= MIN_TOPICS && this.pieceCount() >= MIN_PIECES,
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
