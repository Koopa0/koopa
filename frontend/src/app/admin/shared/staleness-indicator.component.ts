import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

@Component({
  selector: 'app-staleness-indicator',
  standalone: true,
  template: `
    <span class="text-xs font-medium" [class]="colorClass()">
      {{ label() }}
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StalenessIndicatorComponent {
  readonly days = input.required<number>();

  protected readonly colorClass = computed(() => {
    const d = this.days();
    if (d <= 3) return 'text-emerald-400';
    if (d <= 7) return 'text-amber-400';
    if (d <= 13) return 'text-orange-400';
    return 'text-red-400';
  });

  protected readonly label = computed(() => {
    const d = this.days();
    if (d <= 7) return `${d}d ago`;
    return `${d}d stale`;
  });
}
