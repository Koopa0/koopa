import {
  Component,
  ChangeDetectionStrategy,
  computed,
  inject,
  OnInit,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { environment } from '../../../environments/environment';
import { TopicService } from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiTopic } from '../../core/models';

/**
 * The topic index — a quiet hairline list of every topic (name · count ·
 * description), the thematic axis of the writing.
 */
@Component({
  selector: 'app-topics',
  imports: [RouterLink],
  templateUrl: './topics.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TopicsComponent implements OnInit {
  private readonly topicService = inject(TopicService);
  private readonly seoService = inject(SeoService);

  private readonly topicsResource = rxResource<ApiTopic[], void>({
    stream: () => this.topicService.getAllTopics(),
  });

  // Guarded reads — a bare value() throws on a failed load and kills the error
  // UI (project gotcha: "rxResource value() throws — guard it").
  protected readonly topics = computed(() =>
    this.topicsResource.hasValue() ? this.topicsResource.value() : [],
  );

  protected readonly isLoading = computed(
    () => this.topicsResource.status() === 'loading',
  );

  protected readonly error = computed(() =>
    this.topicsResource.status() === 'error'
      ? 'Failed to load topics. Please try again later.'
      : null,
  );

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Topics',
      description: 'Browse all articles, notes, and learning records by topic.',
      ogUrl: `${environment.siteUrl}/topics`,
      jsonLd: buildCollectionPageSchema({
        name: 'Topics',
        description:
          'Browse all articles, notes, and learning records by topic.',
        url: `${environment.siteUrl}/topics`,
      }),
    });
  }
}
