import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { OverlayContainer } from '@angular/cdk/overlay';
import { TooltipDirective } from './tooltip.directive';

@Component({
  imports: [TooltipDirective],
  template: `
    <button
      type="button"
      data-testid="anchor"
      [appTooltip]="tooltipText()"
      [tooltipTestId]="'test-tooltip'"
    >
      Hover me
    </button>
  `,
})
class TestHostComponent {
  readonly tooltipText = signal('Hello tooltip');
}

describe('TooltipDirective', () => {
  let fixture: ComponentFixture<TestHostComponent>;
  let host: TestHostComponent;
  let overlayContainer: OverlayContainer;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TestHostComponent],
    }).compileComponents();

    overlayContainer = TestBed.inject(OverlayContainer);
    fixture = TestBed.createComponent(TestHostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  afterEach(() => {
    overlayContainer.ngOnDestroy?.();
  });

  function anchor(): HTMLElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="anchor"]',
    ) as HTMLElement;
  }

  function tooltipEl(): Element | null {
    return overlayContainer
      .getContainerElement()
      .querySelector('[role="tooltip"]');
  }

  it('should create the host component', () => {
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should not render tooltip bubble when idle', () => {
    expect(tooltipEl()).toBeNull();
  });

  it('should show tooltip bubble on mouseenter', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(tooltipEl()).toBeTruthy();
  });

  it('should display the correct tooltip text on hover', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(tooltipEl()?.textContent?.trim()).toBe('Hello tooltip');
  });

  it('should hide tooltip bubble on mouseleave', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    anchor().dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(tooltipEl()).toBeNull();
  });

  it('should show tooltip on focusin', async () => {
    anchor().dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(tooltipEl()).toBeTruthy();
  });

  it('should hide tooltip on focusout', async () => {
    anchor().dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    anchor().dispatchEvent(new FocusEvent('focusout', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(tooltipEl()).toBeNull();
  });

  it('should hide tooltip when ESC key is pressed', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    anchor().dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
    );
    fixture.detectChanges();
    await fixture.whenStable();

    expect(tooltipEl()).toBeNull();
  });

  it('should set aria-describedby on anchor while tooltip is visible', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(anchor().getAttribute('aria-describedby')).toMatch(
      /^app-tooltip-\d+$/,
    );
  });

  it('should remove aria-describedby after tooltip hides', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    anchor().dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(anchor().getAttribute('aria-describedby')).toBeNull();
  });

  it('should update tooltip text when binding changes while visible', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    host.tooltipText.set('Updated text');
    fixture.detectChanges();
    await fixture.whenStable();

    expect(tooltipEl()?.textContent?.trim()).toBe('Updated text');
  });

  it('should apply tooltipTestId to the overlay wrapper when provided', async () => {
    anchor().dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    fixture.detectChanges();
    await fixture.whenStable();

    const wrapper = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-tooltip"]');
    expect(wrapper).toBeTruthy();
  });
});
