import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { environment } from '../../../environments/environment';
import { TopicService } from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiTopic } from '../../core/models';

@Component({
  selector: 'app-topics',
  imports: [RouterLink],
  templateUrl: './topics.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TopicsComponent implements OnInit {
  private readonly topicService = inject(TopicService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly topics = signal<ApiTopic[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

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
    this.loadTopics();
  }

  private loadTopics(): void {
    this.topicService
      .getAllTopics()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (topics) => {
          this.topics.set(topics);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('Failed to load topics. Please try again later.');
          this.isLoading.set(false);
        },
      });
  }
}
