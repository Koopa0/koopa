import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NavItemComponent } from './nav-item.component';

// ---------------------------------------------------------------------------
// Host component — NavItemComponent uses content projection for [nav-icon]
// ---------------------------------------------------------------------------
@Component({
  standalone: true,
  imports: [NavItemComponent],
  template: `
    <app-nav-item
      [label]="label()"
      [active]="active()"
      [count]="count()"
      [href]="href()"
      [testId]="testId()"
    >
      <svg nav-icon data-testid="nav-icon-svg" viewBox="0 0 16 16">
        <circle cx="8" cy="8" r="6" />
      </svg>
    </app-nav-item>
  `,
})
class HostComponent {
  readonly label = signal('Dashboard');
  readonly active = signal(false);
  readonly count = signal<number | null>(null);
  readonly href = signal<string | null>(null);
  readonly testId = signal<string | null>('nav-dashboard');
}

describe('NavItemComponent', () => {
  let hostFixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostComponent);
    host = hostFixture.componentInstance;
    await hostFixture.whenStable();
  });

  it('should create', () => {
    expect(host).toBeTruthy();
  });

  describe('element type based on href', () => {
    it('should render a button when href is null', async () => {
      host.href.set(null);
      await hostFixture.whenStable();

      const el = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-dashboard"]',
      );
      expect(el.tagName.toLowerCase()).toBe('button');
    });

    it('should render an anchor when href is provided', async () => {
      host.href.set('/dashboard');
      await hostFixture.whenStable();

      const el = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-dashboard"]',
      );
      expect(el.tagName.toLowerCase()).toBe('a');
      expect(el.getAttribute('href')).toBe('/dashboard');
    });
  });

  describe('label', () => {
    it('should render the label text', async () => {
      host.label.set('Orders');
      await hostFixture.whenStable();

      const el = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-dashboard"]',
      );
      expect(el.textContent).toContain('Orders');
    });
  });

  describe('active state', () => {
    it('should not set aria-current when active is false', async () => {
      host.active.set(false);
      await hostFixture.whenStable();

      const el = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-dashboard"]',
      );
      expect(el.getAttribute('aria-current')).toBeNull();
    });

    it('should set aria-current=page when active is true', async () => {
      host.active.set(true);
      await hostFixture.whenStable();

      const el = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-dashboard"]',
      );
      expect(el.getAttribute('aria-current')).toBe('page');
    });

    it('should set aria-current=page on the anchor when href is set and active is true', async () => {
      host.href.set('/orders');
      host.active.set(true);
      await hostFixture.whenStable();

      const el = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-dashboard"]',
      );
      expect(el.tagName.toLowerCase()).toBe('a');
      expect(el.getAttribute('aria-current')).toBe('page');
    });
  });

  describe('count badge', () => {
    it('should not render a count span when count is null', async () => {
      host.count.set(null);
      await hostFixture.whenStable();

      const monospanElements =
        hostFixture.nativeElement.querySelectorAll('.ml-auto');
      expect(monospanElements.length).toBe(0);
    });

    it('should render the count value when count is provided', async () => {
      host.count.set(42);
      await hostFixture.whenStable();

      const countSpan = hostFixture.nativeElement.querySelector('.ml-auto');
      expect(countSpan).toBeTruthy();
      expect(countSpan.textContent.trim()).toBe('42');
    });

    it('should render count of 0 when count is 0', async () => {
      host.count.set(0);
      await hostFixture.whenStable();

      const countSpan = hostFixture.nativeElement.querySelector('.ml-auto');
      expect(countSpan).toBeTruthy();
      expect(countSpan.textContent.trim()).toBe('0');
    });
  });

  describe('content projection', () => {
    it('should project the nav-icon slot content', () => {
      const svg = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-icon-svg"]',
      );
      expect(svg).toBeTruthy();
    });
  });

  describe('testId', () => {
    it('should apply testId attribute when testId is set', async () => {
      host.testId.set('nav-settings');
      await hostFixture.whenStable();

      const el = hostFixture.nativeElement.querySelector(
        '[data-testid="nav-settings"]',
      );
      expect(el).toBeTruthy();
    });

    it('should not render data-testid attribute when testId is null', async () => {
      host.testId.set(null);
      await hostFixture.whenStable();

      // Query specifically button or anchor — the projected svg has its own
      // data-testid="nav-icon-svg" and must not be counted here.
      const el = hostFixture.nativeElement.querySelector(
        'button[data-testid], a[data-testid]',
      );
      expect(el).toBeNull();
    });
  });
});
