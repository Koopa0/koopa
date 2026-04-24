import { Component, ChangeDetectionStrategy, input } from '@angular/core';
import { LoadingSpinnerComponent } from '../loading-spinner/loading-spinner.component';
import { EmptyStateComponent } from '../empty-state/empty-state.component';
import { FileText } from 'lucide-angular';

/**
 * Generic table container: handles loading/empty/error states and frame styles.
 * Table content (thead + tbody) is projected via ng-content.
 *
 * Usage:
 * ```html
 * <app-data-table [isLoading]="loading()" [isEmpty]="items().length === 0" emptyTitle="No data">
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
  readonly emptyTitle = input('No data');
  readonly emptyDescription = input('');
  readonly emptyIcon = input(FileText);
}
