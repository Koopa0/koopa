import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type AlertVariant = 'info' | 'success' | 'warn' | 'error';

const VARIANT_CLASSES: Record<AlertVariant, string> = {
  info: 'bg-info-bg text-info',
  success: 'bg-success-bg text-success',
  warn: 'bg-warn-bg text-warn',
  error: 'bg-error-bg text-error',
};

/**
 * DS inline alert — `ui-alert`. Denser than a callout: icon slot + text.
 * Project an icon into `[alert-icon]` and the message as content.
 */
@Component({
  selector: 'app-alert',
  template: `
    <div [class]="classes()" role="alert" [attr.data-testid]="testId()">
      <span class="mt-px inline-flex shrink-0 [&_svg]:size-4">
        <ng-content select="[alert-icon]" />
      </span>
      <div class="text-fg-muted">
        @if (heading()) {
          <strong class="font-semibold text-current">{{ heading() }}</strong>
        }
        <ng-content />
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AlertComponent {
  readonly variant = input<AlertVariant>('info');
  readonly heading = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() =>
    [
      'flex gap-2.5 rounded-sm px-3 py-2.5 font-sans text-[13px] leading-normal',
      VARIANT_CLASSES[this.variant()],
    ].join(' '),
  );
}
