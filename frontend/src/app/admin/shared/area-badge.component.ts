import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

const AREA_COLORS: Record<string, { bg: string; text: string }> = {
  backend: { bg: 'bg-violet-900/40', text: 'text-violet-300' },
  learning: { bg: 'bg-sky-900/40', text: 'text-sky-300' },
  studio: { bg: 'bg-amber-900/40', text: 'text-amber-300' },
  career: { bg: 'bg-emerald-900/40', text: 'text-emerald-300' },
};

const DEFAULT_COLOR = { bg: 'bg-zinc-800', text: 'text-zinc-300' };

@Component({
  selector: 'app-area-badge',
  standalone: true,
  template: `
    <span
      class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium"
      [class]="colorClasses()"
    >
      {{ area() }}
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AreaBadgeComponent {
  readonly area = input.required<string>();

  protected readonly colorClasses = computed(() => {
    const colors = AREA_COLORS[this.area()] ?? DEFAULT_COLOR;
    return `${colors.bg} ${colors.text}`;
  });
}
