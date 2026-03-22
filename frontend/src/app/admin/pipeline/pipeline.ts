import {
  Component,
  ChangeDetectionStrategy,
  inject,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  RefreshCw,
  GitBranch,
  Rss,
  ShieldCheck,
  Sparkles,
  Newspaper,
  Bookmark,
  Loader2,
} from 'lucide-angular';
import { Observable } from 'rxjs';
import { PipelineService } from '../../core/services/pipeline.service';
import type { PipelineAction } from '../../core/services/pipeline.service';
import { NotificationService } from '../../core/services/notification.service';

interface PipelineCard {
  name: string;
  desc: string;
  icon: typeof RefreshCw;
  action: PipelineAction;
  trigger: () => Observable<unknown>;
}

@Component({
  selector: 'app-pipeline',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './pipeline.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PipelineComponent {
  private readonly pipelineService = inject(PipelineService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly triggering = this.pipelineService.triggering;

  protected readonly Loader2Icon = Loader2;

  protected readonly commonCards: PipelineCard[] = [
    {
      name: 'Notion Sync',
      desc: '同步 Notion tasks, projects, goals',
      icon: RefreshCw,
      action: 'notion-sync',
      trigger: () => this.pipelineService.triggerNotionSync(),
    },
    {
      name: 'Obsidian + GitHub Sync',
      desc: '同步 Obsidian notes 和 GitHub commits',
      icon: GitBranch,
      action: 'sync',
      trigger: () => this.pipelineService.triggerSync(),
    },
    {
      name: 'Collect RSS',
      desc: '從 feeds 收集新內容',
      icon: Rss,
      action: 'collect',
      trigger: () => this.pipelineService.triggerCollect(),
    },
  ];

  protected readonly advancedCards: PipelineCard[] = [
    {
      name: 'Reconcile',
      desc: '調解 Notion 和 local DB 的狀態差異',
      icon: ShieldCheck,
      action: 'reconcile',
      trigger: () => this.pipelineService.triggerReconcile(),
    },
    {
      name: 'AI Generate',
      desc: 'AI 生成內容',
      icon: Sparkles,
      action: 'generate',
      trigger: () => this.pipelineService.triggerGenerate(),
    },
    {
      name: 'Weekly Digest',
      desc: '生成週報/月報',
      icon: Newspaper,
      action: 'digest',
      trigger: () => this.pipelineService.triggerDigest(),
    },
    {
      name: 'Process Bookmarks',
      desc: '處理書籤',
      icon: Bookmark,
      action: 'bookmark',
      trigger: () => this.pipelineService.triggerBookmark(),
    },
  ];

  protected runAction(card: PipelineCard): void {
    card
      .trigger()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success(`${card.name} 完成`),
        error: () => this.notificationService.error(`${card.name} 失敗`),
      });
  }
}
