import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  output,
  signal,
} from '@angular/core';
import { ModalComponent } from '../../../../shared/components/modal/modal.component';

const MAX_REASON_LENGTH = 500;

/** Collects the owner's durable reason before removing a snapshot from public view. */
@Component({
  selector: 'app-withdrawal-reason-dialog',
  imports: [ModalComponent],
  template: `
    <app-modal
      title="Withdraw publication"
      subtitle="The snapshot will stop appearing on Koopa's public surfaces."
      titleId="withdrawal-dialog-title"
      maxWidth="sm"
      (closed)="dismissed.emit()"
    >
      <div class="flex flex-col gap-3">
        <p class="text-xs leading-relaxed text-warn">
          Withdrawal cannot recall copies already received through feeds,
          caches, or third-party archives.
        </p>
        <div class="flex flex-col gap-1">
          <label
            for="withdrawal-reason"
            class="font-mono text-[11px] text-fg-subtle"
          >
            Reason
            <span class="text-fg-faint">({{ reasonLength() }}/{{ maxLength }})</span>
          </label>
          <p id="withdrawal-reason-hint" class="text-[11px] text-fg-faint">
            Required. This reason is retained in the admin audit history.
          </p>
          <textarea
            id="withdrawal-reason"
            required
            [value]="reason()"
            (input)="updateReason($event)"
            rows="4"
            [attr.maxlength]="maxLength"
            aria-describedby="withdrawal-reason-hint"
            class="rounded-sm border border-border bg-elevated px-3 py-2 text-xs text-fg focus:border-brand focus:shadow-[0_0_0_1px_var(--brand)] focus:outline-hidden"
            data-testid="withdraw-reason-textarea"
          ></textarea>
        </div>
      </div>

      <div modal-footer class="flex gap-2">
        <button
          type="button"
          (click)="dismissed.emit()"
          [disabled]="isSubmitting()"
          class="inline-flex items-center rounded-sm border border-border bg-elevated px-3 py-1.5 text-xs text-fg-muted transition-colors hover:bg-overlay hover:text-fg disabled:cursor-not-allowed disabled:opacity-40"
          data-testid="withdraw-cancel"
        >
          Cancel
        </button>
        <button
          type="button"
          (click)="confirmWithdrawal()"
          [disabled]="isSubmitting() || !isValid()"
          class="inline-flex items-center rounded-sm border border-error bg-error-bg px-3 py-1.5 text-xs font-semibold text-error transition-colors hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          data-testid="withdraw-submit"
        >
          {{ isSubmitting() ? 'Withdrawing…' : 'Withdraw' }}
        </button>
      </div>
    </app-modal>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class WithdrawalReasonDialogComponent {
  readonly isSubmitting = input(false);

  readonly confirmed = output<string>();
  readonly dismissed = output<void>();

  protected readonly maxLength = MAX_REASON_LENGTH;
  protected readonly reason = signal('');
  protected readonly reasonLength = computed(
    () => Array.from(this.reason()).length,
  );
  protected readonly isValid = computed(() => {
    const value = this.reason();
    return value.trim().length > 0 && this.reasonLength() <= MAX_REASON_LENGTH;
  });

  protected updateReason(event: Event): void {
    this.reason.set((event.target as HTMLTextAreaElement).value);
  }

  protected confirmWithdrawal(): void {
    if (!this.isValid() || this.isSubmitting()) return;
    this.confirmed.emit(this.reason().trim());
  }
}
