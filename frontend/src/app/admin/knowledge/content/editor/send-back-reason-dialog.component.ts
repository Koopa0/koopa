import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  output,
  signal,
} from '@angular/core';
import { ModalComponent } from '../../../../shared/components/modal/modal.component';

const MIN_NOTE_LENGTH = 10;
const MAX_NOTE_LENGTH = 500;

/**
 * Dialog for the owner to enter a reason when sending content back from
 * review to the proposing agent for revision.
 *
 * Emits `submit` with the review note string when the owner confirms,
 * or `cancel` when dismissed. The host is responsible for showing and
 * hiding this component via `@if`.
 */
@Component({
  selector: 'app-send-back-reason-dialog',
  imports: [ModalComponent],
  template: `
    <app-modal
      title="Send back for revision"
      subtitle="The agent will receive this note and revise the content."
      titleId="send-back-dialog-title"
      maxWidth="sm"
      (closed)="dismissed.emit()"
    >
      <div class="flex flex-col gap-3">
        <div class="flex flex-col gap-1">
          <label
            for="send-back-reason"
            class="font-mono text-[11px] text-fg-subtle"
          >
            Revision note
            <span class="text-fg-faint">({{ noteLength() }}/{{ maxLength }})</span>
          </label>
          <textarea
            id="send-back-reason"
            [value]="note()"
            (input)="updateNote($event)"
            rows="4"
            [attr.maxlength]="maxLength"
            placeholder="Describe what the agent should change…"
            class="rounded-sm border border-border bg-elevated px-3 py-2 text-xs text-fg placeholder:text-fg-faint focus:border-brand focus:shadow-[0_0_0_1px_var(--brand)] focus:outline-hidden"
            data-testid="send-back-reason-textarea"
            aria-describedby="send-back-reason-hint"
          ></textarea>
          @if (showLengthHint()) {
            <p
              id="send-back-reason-hint"
              class="text-[11px] text-fg-faint"
            >
              Minimum {{ minLength }} characters required.
            </p>
          }
        </div>
      </div>

      <div modal-footer class="flex gap-2">
        <button
          type="button"
          (click)="dismissed.emit()"
          [disabled]="isSubmitting()"
          class="inline-flex items-center rounded-sm border border-border bg-elevated px-3 py-1.5 text-xs text-fg-muted transition-colors hover:bg-overlay hover:text-fg disabled:cursor-not-allowed disabled:opacity-40"
          data-testid="send-back-cancel"
        >
          Cancel
        </button>
        <button
          type="button"
          (click)="confirmSendBack()"
          [disabled]="isSubmitting() || !isValid()"
          class="inline-flex items-center rounded-sm border border-brand bg-brand px-3 py-1.5 text-xs font-semibold text-[oklch(0.14_0.02_260)] transition-colors hover:bg-brand-strong disabled:cursor-not-allowed disabled:opacity-40"
          data-testid="send-back-submit"
        >
          {{ isSubmitting() ? 'Sending…' : 'Send back' }}
        </button>
      </div>
    </app-modal>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SendBackReasonDialogComponent {
  readonly isSubmitting = input(false);

  readonly confirmed = output<string>();
  readonly dismissed = output<void>();

  protected readonly minLength = MIN_NOTE_LENGTH;
  protected readonly maxLength = MAX_NOTE_LENGTH;

  protected readonly note = signal('');
  protected readonly noteLength = computed(() => this.note().length);
  protected readonly isValid = computed(
    () =>
      this.noteLength() >= MIN_NOTE_LENGTH &&
      this.noteLength() <= MAX_NOTE_LENGTH,
  );
  /** Show hint once the user has typed something but not yet met the minimum. */
  protected readonly showLengthHint = computed(
    () => this.noteLength() > 0 && this.noteLength() < MIN_NOTE_LENGTH,
  );

  protected updateNote(event: Event): void {
    this.note.set((event.target as HTMLTextAreaElement).value);
  }

  protected confirmSendBack(): void {
    if (!this.isValid() || this.isSubmitting()) return;
    this.confirmed.emit(this.note().trim());
  }
}
