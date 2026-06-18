import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  computed,
  viewChild,
  ElementRef,
} from '@angular/core';
import { A11yModule } from '@angular/cdk/a11y';
import { OverlayModule, type ConnectedPosition } from '@angular/cdk/overlay';

const MENU_POSITIONS: ConnectedPosition[] = [
  {
    originX: 'start',
    originY: 'bottom',
    overlayX: 'start',
    overlayY: 'top',
    offsetY: 6,
  },
  {
    originX: 'end',
    originY: 'bottom',
    overlayX: 'end',
    overlayY: 'top',
    offsetY: 6,
  },
  {
    originX: 'start',
    originY: 'top',
    overlayX: 'start',
    overlayY: 'bottom',
    offsetY: -6,
  },
  {
    originX: 'end',
    originY: 'top',
    overlayX: 'end',
    overlayY: 'bottom',
    offsetY: -6,
  },
];

/**
 * DS dropdown menu — `ui-menu`. Project the trigger into `[menu-trigger]` and
 * `app-menu-item` rows as default content. Clicking the trigger opens a CDK
 * overlay panel (`role=menu`) anchored to the trigger; it closes on backdrop
 * click, ESC, or selecting an item. Focus is trapped while open.
 */
@Component({
  selector: 'app-menu',
  imports: [A11yModule, OverlayModule],
  host: {
    '(click)': 'toggle()',
    '(keydown.arrowdown)': 'onArrowDown($event)',
  },
  template: `
    <!-- Plain positioning anchor: the projected [menu-trigger] (a real button)
         is the interactive control; activation is handled on the host so we
         never nest interactive elements. -->
    <div #trigger class="inline-flex">
      <ng-content select="[menu-trigger]" />
    </div>

    <ng-template
      cdkConnectedOverlay
      [cdkConnectedOverlayOrigin]="triggerEl()"
      [cdkConnectedOverlayOpen]="isOpen()"
      [cdkConnectedOverlayPositions]="positions"
      [cdkConnectedOverlayHasBackdrop]="true"
      cdkConnectedOverlayBackdropClass="cdk-overlay-transparent-backdrop"
      [cdkConnectedOverlayPush]="true"
      (backdropClick)="close()"
      (overlayKeydown)="onOverlayKeydown($event)"
      (detach)="close()"
    >
      <div
        role="menu"
        tabindex="0"
        cdkTrapFocus
        cdkTrapFocusAutoCapture
        [attr.aria-label]="ariaLabel()"
        [attr.data-testid]="testId()"
        [class]="panelClasses"
        (click)="onItemSelect($event)"
        (keydown.enter)="onItemSelect($event)"
        (keydown.space)="onItemSelect($event)"
      >
        <ng-content />
      </div>
    </ng-template>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MenuComponent {
  /** Two-way open state — parents may control or observe it. */
  readonly open = model(false);
  readonly ariaLabel = input<string | null>(null);
  readonly testId = input<string | null>(null);

  protected readonly positions = MENU_POSITIONS;
  protected readonly panelClasses =
    'flex min-w-[180px] flex-col gap-0.5 rounded-md border border-border bg-elevated p-1 shadow-[var(--shadow-1)]';

  private readonly triggerRef =
    viewChild.required<ElementRef<HTMLElement>>('trigger');

  protected readonly isOpen = computed(() => this.open());

  /** CDK origin: the bare element the overlay anchors to. */
  protected readonly triggerEl = computed(
    () => this.triggerRef().nativeElement,
  );

  protected toggle(): void {
    this.open.update((v) => !v);
  }

  protected onArrowDown(event: Event): void {
    event.preventDefault();
    if (!this.open()) {
      this.open.set(true);
    }
  }

  protected close(): void {
    if (this.open()) {
      this.open.set(false);
    }
  }

  protected onOverlayKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.preventDefault();
      this.close();
    }
  }

  /** Close after any enabled menuitem is activated (event delegation). */
  protected onItemSelect(event: Event): void {
    const item = (event.target as HTMLElement).closest('[role="menuitem"]');
    if (item && !item.hasAttribute('disabled')) {
      this.close();
    }
  }
}
