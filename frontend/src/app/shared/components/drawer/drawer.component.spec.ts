import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { DrawerComponent } from './drawer.component';

@Component({
  imports: [DrawerComponent],
  template: `
    <app-drawer
      [(open)]="drawerOpen"
      [testId]="'test-drawer'"
      [ariaLabel]="'Test drawer'"
    >
      <div drawer-header>
        <h2 id="drawer-title">Drawer Title</h2>
      </div>
      <p data-testid="drawer-body">Body content</p>
      <button
        type="button"
        drawer-footer
        data-testid="drawer-cancel"
        (click)="drawerOpen.set(false)"
      >
        Cancel
      </button>
    </app-drawer>
  `,
})
class TestHostComponent {
  readonly drawerOpen = signal(false);
}

describe('DrawerComponent', () => {
  let fixture: ComponentFixture<TestHostComponent>;
  let host: TestHostComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TestHostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(TestHostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  function panel(): HTMLElement | null {
    return fixture.nativeElement.querySelector('[data-testid="test-drawer"]');
  }

  function scrim(): HTMLElement | null {
    return fixture.nativeElement.querySelector(
      '[data-testid="test-drawer-scrim"]',
    );
  }

  it('should create', () => {
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should not render panel when open is false', () => {
    expect(panel()).toBeNull();
  });

  it('should not render scrim when open is false', () => {
    expect(scrim()).toBeNull();
  });

  it('should render panel when open is set to true', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(panel()).toBeTruthy();
  });

  it('should render scrim when open is true', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(scrim()).toBeTruthy();
  });

  it('should have role=dialog on the panel', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(panel()?.getAttribute('role')).toBe('dialog');
  });

  it('should have aria-modal=true on the panel', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(panel()?.getAttribute('aria-modal')).toBe('true');
  });

  it('should set aria-label on the panel', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(panel()?.getAttribute('aria-label')).toBe('Test drawer');
  });

  it('should project header slot content', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    const heading = fixture.nativeElement.querySelector('#drawer-title');
    expect(heading?.textContent).toContain('Drawer Title');
  });

  it('should project body content', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    const body = fixture.nativeElement.querySelector(
      '[data-testid="drawer-body"]',
    );
    expect(body?.textContent).toContain('Body content');
  });

  it('should project footer slot content', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    const cancel = fixture.nativeElement.querySelector(
      '[data-testid="drawer-cancel"]',
    );
    expect(cancel?.textContent).toContain('Cancel');
  });

  it('should close and update open model when scrim is clicked', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    scrim()?.click();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(host.drawerOpen()).toBe(false);
    expect(panel()).toBeNull();
  });

  it('should close when ESC key is pressed on the panel', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    const escEvent = new KeyboardEvent('keydown', {
      key: 'Escape',
      bubbles: true,
    });
    panel()?.dispatchEvent(escEvent);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(host.drawerOpen()).toBe(false);
  });

  it('should re-render panel when open is toggled back to true', async () => {
    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    scrim()?.click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(panel()).toBeNull();

    host.drawerOpen.set(true);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(panel()).toBeTruthy();
  });
});
