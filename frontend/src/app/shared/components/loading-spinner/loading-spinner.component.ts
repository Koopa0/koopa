import { Component, ChangeDetectionStrategy, input } from '@angular/core';

@Component({
  selector: 'app-loading-spinner',
  standalone: true,
  template: `
    <div
      class="animate-spin rounded-full border-current border-t-transparent"
      [class]="sizeClasses()"
      role="status"
      aria-label="載入中"
    >
      <span class="sr-only">載入中</span>
    </div>
  `,
  host: { class: 'inline-flex items-center justify-center' },
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoadingSpinnerComponent {
  readonly size = input<'sm' | 'md' | 'lg'>('md');

  protected sizeClasses(): string {
    switch (this.size()) {
      case 'sm':
        return 'size-3.5 border-2';
      case 'lg':
        return 'size-8 border-[3px]';
      default:
        return 'size-5 border-2';
    }
  }
}
