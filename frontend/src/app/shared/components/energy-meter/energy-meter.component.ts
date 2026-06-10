import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
} from '@angular/core';
import type { EnergyLevel } from '../../../core/models/workbench.model';

/** Ascending bar heights, left to right (design-system energy recipe). */
const BAR_HEIGHT_CLASSES = ['h-[5px]', 'h-[8px]', 'h-[11px]'] as const;

/** How many bars light up per level. */
const LIT_COUNT: Record<EnergyLevel, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

/** Lit-bar color per level; unlit bars stay on the border-strong token. */
const LIT_COLOR_CLASS: Record<EnergyLevel, string> = {
  low: 'bg-fg-subtle',
  medium: 'bg-info',
  high: 'bg-warn',
};

/**
 * Three-bar energy indicator for todos and plan items. Bars light from
 * the left — one for low, two for medium, all three for high — using
 * the semantic color of the level; the rest stay neutral.
 */
@Component({
  selector: 'app-energy-meter',
  standalone: true,
  template: `
    <span
      class="inline-flex items-end gap-[2px]"
      role="img"
      [attr.aria-label]="'Energy: ' + level()"
    >
      @for (barClass of barClasses(); track $index) {
        <span class="w-[3px] rounded-[1px]" [class]="barClass"></span>
      }
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EnergyMeterComponent {
  readonly level = input.required<EnergyLevel>();

  protected readonly barClasses = computed(() => {
    const level = this.level();
    return BAR_HEIGHT_CLASSES.map((height, index) =>
      index < LIT_COUNT[level]
        ? `${height} ${LIT_COLOR_CLASS[level]}`
        : `${height} bg-border-strong`,
    );
  });
}
