import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type MenuItemVariant = 'default' | 'danger';

/**
 * DS menu item — a single row inside `app-menu`. `role=menuitem`, icon slot +
 * label content. `danger` variant tints the row red for destructive actions.
 * Disabled rows are non-interactive and dimmed.
 */
@Component({
  selector: 'app-menu-item',
  template: `
    <button
      type="button"
      role="menuitem"
      [disabled]="disabled() || null"
      [attr.aria-disabled]="disabled() || null"
      [attr.data-testid]="testId()"
      [class]="classes()"
    >
      <span class="inline-flex shrink-0 [&_svg]:size-4">
        <ng-content select="[menu-item-icon]" />
      </span>
      <span class="flex-1 truncate text-left">
        <ng-content />
      </span>
    </button>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MenuItemComponent {
  readonly variant = input<MenuItemVariant>('default');
  readonly disabled = input(false);
  readonly testId = input<string | null>(null);

  protected readonly classes = computed(() => {
    const tone =
      this.variant() === 'danger'
        ? 'text-error hover:bg-error-bg hover:text-error'
        : 'text-fg-muted hover:bg-overlay hover:text-fg';
    return [
      'flex w-full cursor-pointer items-center gap-2.5 rounded-sm border-none bg-transparent',
      'px-2.5 py-[7px] font-sans text-[13px] leading-none whitespace-nowrap',
      'transition-colors duration-[120ms]',
      'disabled:cursor-not-allowed disabled:opacity-40 disabled:pointer-events-none',
      tone,
    ].join(' ');
  });
}
