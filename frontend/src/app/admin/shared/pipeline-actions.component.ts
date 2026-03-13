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
  Loader2,
  RotateCcw,
  Activity,
} from 'lucide-angular';
import { PipelineService } from '../../core/services/pipeline.service';
import { NotificationService } from '../../core/services/notification.service';

interface PipelineButton {
  action: () => void;
  actionKey: string;
  label: string;
  icon: typeof RefreshCw;
}

@Component({
  selector: 'app-pipeline-actions',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    <div class="flex flex-wrap gap-2">
      @for (btn of buttons; track btn.actionKey) {
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-sm border border-zinc-700 px-3 py-2 text-sm text-zinc-300 transition-colors hover:bg-zinc-800 disabled:opacity-50"
          (click)="btn.action()"
          [disabled]="triggering() !== null"
        >
          @if (triggering() === btn.actionKey) {
            <lucide-icon [img]="Loader2Icon" [size]="14" class="animate-spin" />
          } @else {
            <lucide-icon [img]="btn.icon" [size]="14" />
          }
          {{ btn.label }}
        </button>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PipelineActionsComponent {
  private readonly pipelineService = inject(PipelineService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly triggering = this.pipelineService.triggering;
  protected readonly Loader2Icon = Loader2;

  protected readonly buttons: PipelineButton[] = [
    {
      action: () => this.trigger('sync', 'Obsidian 同步已觸發', '同步觸發失敗'),
      actionKey: 'sync',
      label: 'Obsidian',
      icon: RefreshCw,
    },
    {
      action: () => this.trigger('collect', 'RSS 收集已觸發', '收集觸發失敗'),
      actionKey: 'collect',
      label: 'RSS',
      icon: RotateCcw,
    },
    {
      action: () => this.trigger('notion-sync', 'Notion 同步已觸發', 'Notion 同步失敗'),
      actionKey: 'notion-sync',
      label: 'Notion',
      icon: RefreshCw,
    },
    {
      action: () => this.trigger('reconcile', '全量比對已觸發', '比對觸發失敗'),
      actionKey: 'reconcile',
      label: 'Reconcile',
      icon: RotateCcw,
    },
    {
      action: () => this.trigger('bookmark', '書籤生成已觸發', '書籤生成失敗'),
      actionKey: 'bookmark',
      label: 'Bookmark',
      icon: Activity,
    },
  ];

  private trigger(action: string, successMsg: string, errorMsg: string): void {
    const methodMap: Record<string, () => ReturnType<typeof this.pipelineService.triggerSync>> = {
      sync: () => this.pipelineService.triggerSync(),
      collect: () => this.pipelineService.triggerCollect(),
      'notion-sync': () => this.pipelineService.triggerNotionSync(),
      reconcile: () => this.pipelineService.triggerReconcile(),
      bookmark: () => this.pipelineService.triggerBookmark(),
    };

    methodMap[action]()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success(successMsg),
        error: () => this.notificationService.error(errorMsg),
      });
  }
}
