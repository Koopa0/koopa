import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type CardPadding = 'none' | 'md' | 'lg';

/**
 * DS card / surface — `ui-card`. Panel background + hairline border, r-md
 * (r-lg when padding=lg). Optional title/description header; project a
 * `[card-footer]` slot for the hairline-separated footer.
 */
@Component({
  selector: 'app-card',
  template: `
    <div [class]="classes()" [attr.data-testid]="testId()">
      @if (title()) {
        <div class="mb-3 flex items-start justify-between gap-3">
          <div>
            <h3
              class="font-display text-xl leading-snug font-semibold tracking-[-0.01em] text-fg"
            >
              {{ title() }}
            </h3>
            @if (description()) {
              <p
                class="mt-1 font-sans text-[13px] leading-normal text-fg-subtle"
              >
                {{ description() }}
              </p>
            }
          </div>
          <ng-content select="[card-actions]" />
        </div>
      }
      <ng-content />
      <ng-content select="[card-footer]" />
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CardComponent {
  readonly title = input<string | null>(null);
  readonly description = input<string | null>(null);
  readonly hoverable = input(false);
  readonly padding = input<CardPadding>('md');
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() => {
    const pad =
      this.padding() === 'none'
        ? 'p-0'
        : this.padding() === 'lg'
          ? 'p-6'
          : 'p-4';
    const radius = this.padding() === 'lg' ? 'rounded-lg' : 'rounded-md';
    return [
      'box-border border border-border bg-panel transition-colors duration-[120ms]',
      radius,
      pad,
      this.hoverable() ? 'hover:border-border-strong hover:bg-elevated' : '',
    ]
      .filter(Boolean)
      .join(' ');
  });
}
