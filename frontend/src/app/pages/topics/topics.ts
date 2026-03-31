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
import { LucideAngularModule, Hash, Layers } from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { TopicService } from '../../core/services/topic.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiTopic } from '../../core/models';

@Component({
  selector: 'app-topics',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
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

  protected readonly HashIcon = Hash;
  protected readonly LayersIcon = Layers;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: '主題',
      description: '依主題瀏覽所有技術文章、筆記與學習紀錄。',
      ogUrl: `${environment.siteUrl}/topics`,
      jsonLd: buildCollectionPageSchema({
        name: '主題',
        description: '依主題瀏覽所有技術文章、筆記與學習紀錄。',
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
          this.error.set('無法載入主題列表，請稍後再試。');
          this.isLoading.set(false);
        },
      });
  }
}
