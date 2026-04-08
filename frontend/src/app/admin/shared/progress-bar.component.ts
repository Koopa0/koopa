import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

@Component({
  selector: 'app-progress-bar',
  standalone: true,
  template: `
    <div class="flex items-center gap-2">
      <div
        class="flex-1 overflow-hidden rounded-full"
        [class]="size() === 'sm' ? 'h-1.5' : 'h-2.5'"
        [style.background-color]="'rgb(39 39 42)'"
      >
        <div
          class="h-full rounded-full bg-emerald-500 transition-all duration-300"
          [style.width.%]="percentage()"
        ></div>
      </div>
      <span
        class="shrink-0 tabular-nums text-zinc-400"
        [class]="size() === 'sm' ? 'text-xs' : 'text-sm'"
      >
        {{ current() }}/{{ total() }}
      </span>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProgressBarComponent {
  readonly current = input.required<number>();
  readonly total = input.required<number>();
  readonly size = input<'sm' | 'md'>('sm');

  protected readonly percentage = computed(() => {
    const t = this.total();
    if (t <= 0) return 0;
    return Math.min(100, Math.round((this.current() / t) * 100));
  });
}
