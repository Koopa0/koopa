import {
  Component,
  ChangeDetectionStrategy,
  input,
  output,
  computed,
} from '@angular/core';
import type { Toast, ToastVariant } from './toast.service';

const ICON_CLASSES: Record<ToastVariant, string> = {
  default: 'text-brand',
  success: 'text-success',
  error: 'text-error',
};

/**
 * DS toast card — `ui-toast`. A single notification row inside
 * `app-toast-host`: leading variant-tinted icon slot, title + optional
 * description, and a trailing close button. Presentational only — emits
 * `dismiss` for the host/service to remove it from the queue.
 */
@Component({
  selector: 'app-toast',
  template: `
    <div
      class="flex min-w-[280px] max-w-[380px] gap-2.5 rounded-md border border-border bg-elevated p-3 shadow-[var(--shadow-2)]"
      [attr.data-testid]="testId()"
    >
      <span
        class="mt-px inline-flex shrink-0 [&_svg]:size-4"
        [class]="iconClass()"
        aria-hidden="true"
      >
        <ng-content select="[toast-icon]" />
      </span>
      <div class="min-w-0 flex-1">
        <div class="font-sans text-[13px] font-semibold text-fg">
          {{ toast().title }}
        </div>
        @if (toast().desc) {
          <div
            class="mt-0.5 font-sans text-[12px] leading-normal text-fg-subtle"
          >
            {{ toast().desc }}
          </div>
        }
      </div>
      <button
        type="button"
        class="ml-auto inline-flex size-5 shrink-0 cursor-pointer items-center justify-center rounded-sm border-none bg-transparent text-fg-faint transition-colors duration-[120ms] hover:text-fg [&_svg]:size-3.5"
        [attr.aria-label]="closeLabel()"
        [attr.data-testid]="testId() ? testId() + '-close' : 'toast-close'"
        (click)="dismiss.emit(toast().id)"
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          aria-hidden="true"
        >
          <path d="M6 6l12 12M18 6L6 18" />
        </svg>
      </button>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ToastComponent {
  readonly toast = input.required<Toast>();
  readonly closeLabel = input('Dismiss notification');
  readonly testId = input<string | null>(null);

  readonly dismiss = output<number>();

  protected readonly iconClass = computed(
    () => ICON_CLASSES[this.toast().variant],
  );
}
