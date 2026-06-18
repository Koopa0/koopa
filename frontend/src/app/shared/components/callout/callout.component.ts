import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type CalloutVariant = 'brand' | 'note' | 'warn' | 'success' | 'error';

const RULE_CLASSES: Record<CalloutVariant, string> = {
  brand: 'border-l-brand',
  note: 'border-l-fg-subtle',
  warn: 'border-l-warn',
  success: 'border-l-success',
  error: 'border-l-error',
};

const LABEL_CLASSES: Record<CalloutVariant, string> = {
  brand: 'text-brand',
  note: 'text-fg-subtle',
  warn: 'text-warn',
  success: 'text-success',
  error: 'text-error',
};

/**
 * DS callout / admonition — `ui-callout`. Left brand rule, mono label, serif
 * body (the reading-surface voice). Project the body as content.
 */
@Component({
  selector: 'app-callout',
  template: `
    <div [class]="containerClasses()" [attr.data-testid]="testId()">
      @if (label()) {
        <div
          class="mb-1.5 font-mono text-[11px] tracking-[0.06em] uppercase"
          [class]="labelClasses()"
        >
          {{ label() }}
        </div>
      }
      <div class="m-0 font-serif text-[17px] leading-[1.75] text-fg-muted">
        <ng-content />
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CalloutComponent {
  readonly variant = input<CalloutVariant>('brand');
  readonly label = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected readonly containerClasses = computed(() =>
    [
      'rounded-r-md border border-l-[3px] border-border bg-panel px-[18px] py-3.5',
      RULE_CLASSES[this.variant()],
    ].join(' '),
  );

  protected readonly labelClasses = computed(
    () => LABEL_CLASSES[this.variant()],
  );
}
