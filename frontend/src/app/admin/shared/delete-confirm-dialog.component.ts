import {
  Component,
  ChangeDetectionStrategy,
  input,
  output,
  afterNextRender,
  viewChild,
  ElementRef,
} from '@angular/core';
import { A11yModule } from '@angular/cdk/a11y';
import {
  LucideAngularModule,
  AlertTriangle,
} from 'lucide-angular';

@Component({
  selector: 'app-delete-confirm-dialog',
  standalone: true,
  imports: [LucideAngularModule, A11yModule],
  template: `
    <!-- Backdrop (non-interactive overlay) -->
    <div class="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs" aria-hidden="true"></div>

    <!-- Dialog positioner -->
    <div
      class="fixed inset-0 z-50 flex items-center justify-center"
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-dialog-title"
      (keydown.escape)="cancelled.emit()"
    >
      <div
        class="mx-4 w-full max-w-md rounded-sm border border-zinc-700 bg-zinc-900 p-6 shadow-lg"
        cdkTrapFocus
        cdkTrapFocusAutoCapture
        #dialogPanel
      >
        <div class="mb-4 flex items-center gap-3">
          <div class="rounded-full bg-red-900/30 p-2">
            <lucide-icon
              [img]="AlertTriangleIcon"
              [size]="20"
              class="text-red-400"
            />
          </div>
          <h3 id="delete-dialog-title" class="text-lg font-semibold text-zinc-100">
            Confirm Delete {{ entityType() }}
          </h3>
        </div>

        <p class="mb-6 text-sm text-zinc-400">
          Are you sure you want to delete "<span class="font-medium text-zinc-200">{{ entityTitle() }}</span>"?
          This action cannot be undone.
        </p>

        <div class="flex justify-end gap-3">
          <button
            type="button"
            class="rounded-sm border border-zinc-700 px-4 py-2 text-sm text-zinc-300 transition-colors hover:bg-zinc-800"
            (click)="cancelled.emit()"
            [disabled]="isDeleting()"
          >
            Cancel
          </button>
          <button
            type="button"
            class="rounded-sm bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50"
            (click)="confirmed.emit()"
            [disabled]="isDeleting()"
          >
            @if (isDeleting()) {
              <span class="flex items-center gap-2">
                <span
                  class="size-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
                ></span>
                Deleting...
              </span>
            } @else {
              Confirm Delete
            }
          </button>
        </div>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DeleteConfirmDialogComponent {
  readonly entityType = input.required<string>();
  readonly entityTitle = input.required<string>();
  readonly isDeleting = input(false);

  readonly confirmed = output();
  readonly cancelled = output();

  private readonly dialogPanel = viewChild.required<ElementRef>('dialogPanel');

  protected readonly AlertTriangleIcon = AlertTriangle;

  constructor() {
    afterNextRender(() => {
      this.dialogPanel().nativeElement.focus();
    });
  }
}
