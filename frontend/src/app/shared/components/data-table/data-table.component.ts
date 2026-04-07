import { Component, ChangeDetectionStrategy, input } from '@angular/core';
import { LoadingSpinnerComponent } from '../loading-spinner/loading-spinner.component';
import { EmptyStateComponent } from '../empty-state/empty-state.component';
import { FileText } from 'lucide-angular';

/**
 * 通用表格容器：處理 loading/empty/error 狀態和外框樣式。
 * 表格內容（thead + tbody）透過 ng-content 投影。
 *
 * 用法：
 * ```html
 * <app-data-table [isLoading]="loading()" [isEmpty]="items().length === 0" emptyTitle="尚無資料">
 *   <table class="w-full">
 *     <thead>...</thead>
 *     <tbody>...</tbody>
 *   </table>
 * </app-data-table>
 * ```
 */
@Component({
  selector: 'app-data-table',
  standalone: true,
  imports: [LoadingSpinnerComponent, EmptyStateComponent],
  template: `
    @if (error()) {
      <div
        class="mb-4 rounded-xs border border-red-800 bg-red-900/20 px-4 py-3 text-sm text-red-400"
        role="alert"
      >
        {{ error() }}
      </div>
    }

    @if (isLoading()) {
      <div class="flex items-center justify-center py-16">
        <app-loading-spinner size="lg" class="text-zinc-500" />
      </div>
    } @else if (isEmpty()) {
      <app-empty-state
        [icon]="emptyIcon()"
        [title]="emptyTitle()"
        [description]="emptyDescription()"
      >
        <ng-content select="[empty-action]" />
      </app-empty-state>
    } @else {
      <div
        class="overflow-x-auto rounded-xs border border-zinc-800 bg-zinc-900/50"
      >
        <ng-content />
      </div>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DataTableComponent {
  readonly isLoading = input(false);
  readonly isEmpty = input(false);
  readonly error = input('');
  readonly emptyTitle = input('尚無資料');
  readonly emptyDescription = input('');
  readonly emptyIcon = input(FileText);
}
