import {
  Directive,
  ElementRef,
  inject,
  input,
  signal,
  effect,
  OnDestroy,
} from '@angular/core';
import {
  Overlay,
  OverlayRef,
  type ConnectedPosition,
} from '@angular/cdk/overlay';
import { ComponentPortal } from '@angular/cdk/portal';
import {
  Component,
  ChangeDetectionStrategy,
  input as cmpInput,
} from '@angular/core';

const TOOLTIP_POSITIONS: readonly ConnectedPosition[] = [
  {
    originX: 'center',
    originY: 'top',
    overlayX: 'center',
    overlayY: 'bottom',
    offsetY: -6,
  },
  {
    originX: 'center',
    originY: 'bottom',
    overlayX: 'center',
    overlayY: 'top',
    offsetY: 6,
  },
];

let tooltipUid = 0;

/**
 * Internal bubble rendered into the CDK overlay by {@link TooltipDirective}.
 * `role=tooltip`; the host wires `aria-describedby` to its id.
 */
@Component({
  selector: 'app-tooltip',
  template: `
    <div
      role="tooltip"
      [id]="tooltipId()"
      class="pointer-events-none rounded-sm border border-border bg-overlay px-2 py-1 font-sans text-[11px] leading-none text-fg shadow-[var(--shadow-1)]"
    >
      {{ text() }}
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TooltipComponent {
  readonly text = cmpInput('');
  readonly tooltipId = cmpInput('');
}

/**
 * DS tooltip — `[appTooltip]`. Shows a CDK overlay bubble on hover/focus,
 * positioned above the host with a below fallback. Hidden on
 * blur/mouseleave/ESC. Wires `aria-describedby` while visible so screen
 * readers announce the description.
 */
@Directive({
  selector: '[appTooltip]',
  host: {
    '(mouseenter)': 'show()',
    '(mouseleave)': 'hide()',
    '(focusin)': 'show()',
    '(focusout)': 'hide()',
    '(keydown.escape)': 'hide()',
    '[attr.aria-describedby]': 'describedBy()',
  },
})
export class TooltipDirective implements OnDestroy {
  readonly appTooltip = input.required<string>();
  readonly tooltipTestId = input<string | null>(null);

  private readonly overlay = inject(Overlay);
  private readonly host = inject(ElementRef<HTMLElement>);

  private overlayRef: OverlayRef | null = null;
  private readonly id = `app-tooltip-${tooltipUid++}`;

  /** Non-null only while the bubble is visible — drives aria-describedby. */
  protected readonly describedBy = signal<string | null>(null);

  constructor() {
    // Keep a live bubble's text in sync if the binding changes mid-hover.
    effect(() => {
      const text = this.appTooltip();
      if (this.overlayRef?.hasAttached()) {
        this.attachBubble(text);
      }
    });
  }

  protected show(): void {
    const text = this.appTooltip();
    if (!text || this.overlayRef?.hasAttached()) return;

    if (!this.overlayRef) {
      const positionStrategy = this.overlay
        .position()
        .flexibleConnectedTo(this.host)
        .withPush(true)
        .withPositions([...TOOLTIP_POSITIONS]);

      this.overlayRef = this.overlay.create({
        positionStrategy,
        scrollStrategy: this.overlay.scrollStrategies.reposition(),
        hasBackdrop: false,
      });
    }

    this.attachBubble(text);
    this.describedBy.set(this.id);
  }

  protected hide(): void {
    if (this.overlayRef?.hasAttached()) {
      this.overlayRef.detach();
    }
    this.describedBy.set(null);
  }

  private attachBubble(text: string): void {
    if (!this.overlayRef) return;
    if (this.overlayRef.hasAttached()) {
      this.overlayRef.detach();
    }
    const portal = new ComponentPortal(TooltipComponent);
    const ref = this.overlayRef.attach(portal);
    ref.setInput('text', text);
    ref.setInput('tooltipId', this.id);
    if (this.tooltipTestId()) {
      ref.location.nativeElement.setAttribute(
        'data-testid',
        this.tooltipTestId(),
      );
    }
  }

  ngOnDestroy(): void {
    this.overlayRef?.dispose();
    this.overlayRef = null;
  }
}
