import { Component, input, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'app-skeleton',
  standalone: true,
  template: `
    @switch (variant()) {
      @case ('card') {
        <div
          class="overflow-hidden rounded-sm border border-zinc-800 bg-zinc-900/50"
        >
          <div class="p-6">
            <div class="mb-3 flex gap-2">
              <div class="h-4 w-12 animate-pulse rounded-sm bg-zinc-800"></div>
              <div class="h-4 w-16 animate-pulse rounded-sm bg-zinc-800"></div>
            </div>
            <div
              class="mb-2 h-6 w-3/4 animate-pulse rounded-sm bg-zinc-800"
            ></div>
            <div
              class="mb-1 h-4 w-full animate-pulse rounded-sm bg-zinc-800"
            ></div>
            <div class="h-4 w-2/3 animate-pulse rounded-sm bg-zinc-800"></div>
          </div>
          <div class="flex gap-4 border-t border-zinc-800/60 px-6 py-3">
            <div class="h-3 w-20 animate-pulse rounded-sm bg-zinc-800"></div>
            <div class="h-3 w-14 animate-pulse rounded-sm bg-zinc-800"></div>
            <div
              class="ml-auto h-3 w-10 animate-pulse rounded-sm bg-zinc-800"
            ></div>
          </div>
        </div>
      }
      @case ('text') {
        <div class="space-y-3">
          <div class="h-4 w-full animate-pulse rounded-sm bg-zinc-800"></div>
          <div class="h-4 w-5/6 animate-pulse rounded-sm bg-zinc-800"></div>
          <div class="h-4 w-4/6 animate-pulse rounded-sm bg-zinc-800"></div>
        </div>
      }
      @case ('article') {
        <div class="space-y-6">
          <div class="h-8 w-2/3 animate-pulse rounded-sm bg-zinc-800"></div>
          <div class="flex gap-4">
            <div class="h-4 w-24 animate-pulse rounded-sm bg-zinc-800"></div>
            <div class="h-4 w-16 animate-pulse rounded-sm bg-zinc-800"></div>
          </div>
          <div class="space-y-3">
            @for (_ of [1, 2, 3, 4, 5, 6]; track _) {
              <div
                class="h-4 animate-pulse rounded-sm bg-zinc-800"
                [style.width]="_ % 3 === 0 ? '85%' : '100%'"
              ></div>
            }
          </div>
        </div>
      }
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SkeletonComponent {
  readonly variant = input<'card' | 'text' | 'article'>('card');
}
