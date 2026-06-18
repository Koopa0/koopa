import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { ToastComponent } from '../toast/toast.component';
import { ToastService } from '../toast/toast.service';

/**
 * DS toast host — `ui-toast-host`. Mount once near the app root. Subscribes to
 * the root `ToastService` signal and renders the live stack in a fixed,
 * top-center `role=status aria-live=polite` region. Drop-in: no inputs.
 */
@Component({
  selector: 'app-toast-host',
  imports: [ToastComponent],
  template: `
    <div
      class="pointer-events-none fixed inset-x-0 top-4 z-[60] flex flex-col items-center gap-2.5 px-4"
      role="status"
      aria-live="polite"
      aria-atomic="false"
      data-testid="toast-host"
    >
      @for (toast of toasts(); track toast.id) {
        <app-toast
          class="pointer-events-auto"
          [toast]="toast"
          [testId]="'toast-' + toast.id"
          (dismiss)="service.dismiss($event)"
        >
          <svg
            toast-icon
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            @switch (toast.variant) {
              @case ('success') {
                <path d="M20 6L9 17l-5-5" />
              }
              @case ('error') {
                <circle cx="12" cy="12" r="9" />
                <path d="M12 8v5M12 16h.01" />
              }
              @default {
                <circle cx="12" cy="12" r="9" />
                <path d="M12 16v-5M12 8h.01" />
              }
            }
          </svg>
        </app-toast>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ToastHostComponent {
  protected readonly service = inject(ToastService);
  protected readonly toasts = this.service.toasts;
}
