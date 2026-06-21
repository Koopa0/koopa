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
import { LucideAngularModule, ArrowRight, ArrowUpRight } from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { TopicService } from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildWebSiteSchema } from '../../core/services/seo/json-ld.util';
import { contentTypeLabelEn } from '../../core/models';
import type {
  ApiContent,
  ApiListResponse,
  ApiTopic,
} from '../../core/models';

const RECENT_LIMIT = 3;
const RECENT_FETCH = 50;

/** A topic that has at least one published piece, with its latest inline. */
interface ThemeRow {
  topic: ApiTopic;
  count: number;
  /** Newest piece in this topic, only when ≥2 pieces and found in the feed. */
  latest: ApiContent | null;
}

/**
 * The front door (route `''`) — three bands in a single centred column:
 * a positioning statement, the topics rendered as a scaling list ("what
 * I'm working through"), and the three most recent pieces. Topics with no
 * published pieces fold into one honest "Also following" line — no fake
 * counts. The full reading wall lives at /articles.
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

  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly ArrowUpRightIcon = ArrowUpRight;

  protected readonly contentsResource = rxResource<
    ApiListResponse<ApiContent>,
    void
  >({
    stream: () =>
      this.contentService.listPublished({ page: 1, perPage: RECENT_FETCH }),
  });

  protected readonly topicsResource = rxResource<ApiTopic[], void>({
    stream: () => this.topicService.getAllTopics(),
  });

  private readonly contents = computed(() =>
    this.contentsResource.hasValue() ? this.contentsResource.value().data : [],
  );

  private readonly topics = computed(() =>
    this.topicsResource.hasValue() ? this.topicsResource.value() : [],
  );

  protected readonly isLoading = computed(
    () =>
      this.contentsResource.status() === 'loading' ||
      this.topicsResource.status() === 'loading',
  );

  /** Themes with published pieces, sorted by the topic's own sort order. */
  protected readonly themes = computed<ThemeRow[]>(() => {
    const feed = this.contents();
    return this.topics()
      .filter((topic) => topic.content_count > 0)
      .sort((a, b) => a.sort_order - b.sort_order)
      .map((topic) => {
        // The feed is newest-first, so the first match is the latest piece.
        const latest =
          topic.content_count >= 2
            ? feed.find((c) => c.topics.some((t) => t.slug === topic.slug)) ??
              null
            : null;
        return { topic, count: topic.content_count, latest };
      });
  });

  /** Topics with no published pieces — folded into one honest line. */
  protected readonly following = computed(() =>
    this.topics()
      .filter((topic) => topic.content_count === 0)
      .sort((a, b) => a.sort_order - b.sort_order),
  );

  /** The newest pieces across every type. */
  protected readonly recent = computed(() =>
    this.contents().slice(0, RECENT_LIMIT),
  );

  protected readonly typeLabel = contentTypeLabelEn;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'koopa0.dev',
      description: 'Notes, systems, and what I am working out.',
      ogUrl: environment.siteUrl,
      canonicalUrl: environment.siteUrl,
      jsonLd: buildWebSiteSchema(),
    });
  }

  protected primaryTopicName(content: ApiContent): string {
    return content.topics[0]?.name ?? this.typeLabel(content.type);
  }
}
