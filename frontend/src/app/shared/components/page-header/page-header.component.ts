import { Component, ChangeDetectionStrategy, input } from '@angular/core';

@Component({
  selector: 'app-page-header',
  standalone: true,
  template: `
    <section class="border-b border-zinc-800 bg-zinc-950">
      <div class="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div
          class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <div>
            <h1 class="text-2xl font-bold text-zinc-100">{{ title() }}</h1>
            @if (description()) {
              <p class="mt-1 text-sm text-zinc-400">{{ description() }}</p>
            }
          </div>
          <div class="flex items-center gap-3">
            <ng-content />
          </div>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PageHeaderComponent {
  readonly title = input.required<string>();
  readonly description = input('');
}
