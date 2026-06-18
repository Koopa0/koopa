import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { OverlayContainer } from '@angular/cdk/overlay';
import { MenuComponent } from './menu.component';

@Component({
  imports: [MenuComponent],
  template: `
    <app-menu
      [testId]="'test-menu'"
      [(open)]="menuOpen"
      [ariaLabel]="'Actions menu'"
    >
      <button type="button" menu-trigger data-testid="menu-trigger">
        Open
      </button>
      <button type="button" role="menuitem" data-testid="item-edit">
        Edit
      </button>
      <button type="button" role="menuitem" data-testid="item-delete">
        Delete
      </button>
    </app-menu>
  `,
})
class TestHostComponent {
  readonly menuOpen = signal(false);
}

describe('MenuComponent', () => {
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

  it('should create', () => {
    const menuEl = fixture.nativeElement.querySelector('app-menu');
    expect(menuEl).toBeTruthy();
  });

  it('should render trigger content when closed', () => {
    const trigger = fixture.nativeElement.querySelector(
      '[data-testid="menu-trigger"]',
    );
    expect(trigger).toBeTruthy();
    expect(trigger.textContent).toContain('Open');
  });

  it('should not render panel when open is false', () => {
    const panel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    expect(panel).toBeNull();
  });

  it('should open panel when trigger is clicked', async () => {
    const trigger = fixture.nativeElement.querySelector(
      '[data-testid="menu-trigger"]',
    );
    trigger.click();
    fixture.detectChanges();
    await fixture.whenStable();

    const panel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    expect(panel).toBeTruthy();
  });

  it('should set role=menu on the panel when open', async () => {
    const trigger = fixture.nativeElement.querySelector(
      '[data-testid="menu-trigger"]',
    );
    trigger.click();
    fixture.detectChanges();
    await fixture.whenStable();

    const panel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    expect(panel?.getAttribute('role')).toBe('menu');
  });

  it('should set aria-label on the panel when open', async () => {
    const trigger = fixture.nativeElement.querySelector(
      '[data-testid="menu-trigger"]',
    );
    trigger.click();
    fixture.detectChanges();
    await fixture.whenStable();

    const panel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    expect(panel?.getAttribute('aria-label')).toBe('Actions menu');
  });

  it('should close panel when ESC is pressed', async () => {
    const trigger = fixture.nativeElement.querySelector(
      '[data-testid="menu-trigger"]',
    );
    trigger.click();
    fixture.detectChanges();
    await fixture.whenStable();

    const panel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    expect(panel).toBeTruthy();

    const escEvent = new KeyboardEvent('keydown', {
      key: 'Escape',
      bubbles: true,
    });
    panel?.dispatchEvent(escEvent);
    fixture.detectChanges();
    await fixture.whenStable();

    const closedPanel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    expect(closedPanel).toBeNull();
  });

  it('should update open model to true when menu opens', async () => {
    expect(host.menuOpen()).toBe(false);

    const trigger = fixture.nativeElement.querySelector(
      '[data-testid="menu-trigger"]',
    );
    trigger.click();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(host.menuOpen()).toBe(true);
  });

  it('should update open model to false when menu closes via ESC', async () => {
    host.menuOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    const panel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    const escEvent = new KeyboardEvent('keydown', {
      key: 'Escape',
      bubbles: true,
    });
    panel?.dispatchEvent(escEvent);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(host.menuOpen()).toBe(false);
  });

  it('should open with ArrowDown key when closed', async () => {
    const menuEl = fixture.nativeElement.querySelector(
      'app-menu',
    ) as HTMLElement;
    const arrowEvent = new KeyboardEvent('keydown', {
      key: 'ArrowDown',
      bubbles: true,
    });
    menuEl.dispatchEvent(arrowEvent);
    fixture.detectChanges();
    await fixture.whenStable();

    const panel = overlayContainer
      .getContainerElement()
      .querySelector('[data-testid="test-menu"]');
    expect(panel).toBeTruthy();
  });
});
