import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type SeparatorOrientation = 'h' | 'v';

/**
 * DS separator — `ui-separator`. A hairline divider. Horizontal (default) spans
 * full width; vertical stretches to its container's height. An optional `label`
 * (horizontal only) centers a mono caption flanked by hairlines.
 */
@Component({
  selector: 'app-separator',
  template: `
    @if (orientation() === 'h' && label()) {
      <div
        class="flex items-center gap-3"
        role="separator"
        aria-orientation="horizontal"
        [attr.aria-label]="label()"
        [attr.data-testid]="'separator'"
      >
        <span class="h-px flex-1 bg-border" aria-hidden="true"></span>
        <span
          class="font-mono text-[11px] tracking-[0.08em] text-fg-subtle uppercase"
        >
          {{ label() }}
        </span>
        <span class="h-px flex-1 bg-border" aria-hidden="true"></span>
      </div>
    } @else {
      <div
        [class]="lineClasses()"
        role="separator"
        [attr.aria-orientation]="
          orientation() === 'v' ? 'vertical' : 'horizontal'
        "
        [attr.data-testid]="'separator'"
      ></div>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SeparatorComponent {
  readonly orientation = input<SeparatorOrientation>('h');
  readonly label = input<string | null>(null);

  protected readonly lineClasses = computed(() =>
    this.orientation() === 'v'
      ? 'w-px self-stretch bg-border'
      : 'h-px w-full bg-border',
  );
}
