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

@Component({
  selector: 'app-modal',
  standalone: true,
  imports: [A11yModule],
  template: `
    <!-- Backdrop -->
    <div
      class="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs"
      aria-hidden="true"
      (click)="closed.emit()"
    ></div>

    <!-- Dialog positioner -->
    <div
      class="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      [attr.aria-labelledby]="titleId()"
      (keydown.escape)="closed.emit()"
    >
      <div
        class="w-full rounded-xs border border-zinc-700 bg-zinc-900 shadow-lg"
        [class]="maxWidthClass()"
        cdkTrapFocus
        cdkTrapFocusAutoCapture
        #modalPanel
      >
        <!-- Header -->
        @if (title()) {
          <div class="border-b border-zinc-800 px-6 py-4">
            <h3 [id]="titleId()" class="text-lg font-semibold text-zinc-100">
              {{ title() }}
            </h3>
            @if (subtitle()) {
              <p class="mt-0.5 text-sm text-zinc-500">{{ subtitle() }}</p>
            }
          </div>
        }

        <!-- Body -->
        <div class="px-6 py-4">
          <ng-content />
        </div>

        <!-- Footer -->
        <div class="flex justify-end gap-3 border-t border-zinc-800 px-6 py-4">
          <ng-content select="[modal-footer]" />
        </div>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ModalComponent {
  readonly title = input('');
  readonly subtitle = input('');
  readonly titleId = input('modal-title');
  readonly maxWidth = input<'sm' | 'md' | 'lg' | 'xl'>('md');

  readonly closed = output();

  private readonly modalPanel = viewChild.required<ElementRef>('modalPanel');

  protected maxWidthClass(): string {
    switch (this.maxWidth()) {
      case 'sm':
        return 'max-w-sm';
      case 'lg':
        return 'max-w-2xl';
      case 'xl':
        return 'max-w-4xl';
      default:
        return 'max-w-md';
    }
  }

  constructor() {
    afterNextRender(() => {
      this.modalPanel().nativeElement.focus();
    });
  }
}
