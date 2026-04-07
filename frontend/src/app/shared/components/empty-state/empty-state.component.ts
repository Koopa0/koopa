import { Component, ChangeDetectionStrategy, input } from '@angular/core';
import { LucideAngularModule, FileText } from 'lucide-angular';

@Component({
  selector: 'app-empty-state',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    <div class="flex flex-col items-center gap-3 py-16 text-center">
      <lucide-icon [img]="icon()" [size]="40" class="text-zinc-700" />
      <h3 class="text-sm font-medium text-zinc-300">{{ title() }}</h3>
      @if (description()) {
        <p class="max-w-sm text-xs text-zinc-500">{{ description() }}</p>
      }
      <ng-content />
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EmptyStateComponent {
  readonly icon = input(FileText);
  readonly title = input.required<string>();
  readonly description = input('');
}
