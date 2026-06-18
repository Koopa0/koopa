import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SegmentedComponent, SegmentedItem } from './segmented.component';

const ITEMS: readonly SegmentedItem[] = [
  { id: 'day', label: 'Day' },
  { id: 'week', label: 'Week' },
  { id: 'month', label: 'Month' },
];

const ITEMS_WITH_DISABLED: readonly SegmentedItem[] = [
  { id: 'a', label: 'Alpha' },
  { id: 'b', label: 'Beta', disabled: true },
  { id: 'c', label: 'Gamma' },
];

// ---------------------------------------------------------------------------
// Host for standard tests
// ---------------------------------------------------------------------------
@Component({
  standalone: true,
  imports: [SegmentedComponent],
  template: `
    <app-segmented
      [items]="items()"
      [(active)]="active"
      [ariaLabel]="ariaLabel()"
      [testId]="testId()"
    />
  `,
})
class HostComponent {
  readonly items = signal<readonly SegmentedItem[]>(ITEMS);
  readonly active = signal('day');
  readonly ariaLabel = signal<string | null>('View mode');
  readonly testId = signal<string | null>('seg-test');
}

// ---------------------------------------------------------------------------
// Host for disabled-item tests — uses ITEMS_WITH_DISABLED from construction
// ---------------------------------------------------------------------------
@Component({
  standalone: true,
  imports: [SegmentedComponent],
  template: ` <app-segmented [items]="items()" [(active)]="active" /> `,
})
class DisabledHostComponent {
  readonly items = signal<readonly SegmentedItem[]>(ITEMS_WITH_DISABLED);
  readonly active = signal('a');
}

describe('SegmentedComponent', () => {
  let hostFixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  beforeEach(async () => {
    // Import both host components in one configureTestingModule call so nested
    // beforeEach blocks can create DisabledHostComponent without re-configuring.
    await TestBed.configureTestingModule({
      imports: [HostComponent, DisabledHostComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostComponent);
    host = hostFixture.componentInstance;
    await hostFixture.whenStable();
  });

  it('should create', () => {
    expect(host).toBeTruthy();
  });

  it('should render all segment buttons when items are provided', () => {
    const buttons = hostFixture.nativeElement.querySelectorAll('button');
    expect(buttons.length).toBe(3);
  });

  it('should apply aria-label to the group when ariaLabel input is set', () => {
    const group = hostFixture.nativeElement.querySelector('[role="group"]');
    expect(group.getAttribute('aria-label')).toBe('View mode');
  });

  it('should apply testId to the container when testId input is set', () => {
    const group = hostFixture.nativeElement.querySelector(
      '[data-testid="seg-test"]',
    );
    expect(group).toBeTruthy();
  });

  it('should mark the active segment with aria-pressed true', () => {
    const dayBtn = hostFixture.nativeElement.querySelector(
      '[data-testid="segmented-day"]',
    );
    expect(dayBtn.getAttribute('aria-pressed')).toBe('true');
  });

  it('should mark inactive segments with aria-pressed false', () => {
    const weekBtn = hostFixture.nativeElement.querySelector(
      '[data-testid="segmented-week"]',
    );
    expect(weekBtn.getAttribute('aria-pressed')).toBe('false');
  });

  it('should update active model when a segment button is clicked', async () => {
    const weekBtn = hostFixture.nativeElement.querySelector(
      '[data-testid="segmented-week"]',
    ) as HTMLButtonElement;
    weekBtn.click();
    await hostFixture.whenStable();

    expect(host.active()).toBe('week');
  });

  it('should reflect model change back to aria-pressed after click', async () => {
    const weekBtn = hostFixture.nativeElement.querySelector(
      '[data-testid="segmented-week"]',
    ) as HTMLButtonElement;
    weekBtn.click();
    await hostFixture.whenStable();

    expect(weekBtn.getAttribute('aria-pressed')).toBe('true');

    const dayBtn = hostFixture.nativeElement.querySelector(
      '[data-testid="segmented-day"]',
    );
    expect(dayBtn.getAttribute('aria-pressed')).toBe('false');
  });

  it('should render each segment with data-testid based on item id', () => {
    for (const item of ITEMS) {
      const btn = hostFixture.nativeElement.querySelector(
        `[data-testid="segmented-${item.id}"]`,
      );
      expect(btn).toBeTruthy();
      expect(btn.textContent.trim()).toBe(item.label);
    }
  });

  describe('disabled segment', () => {
    let disabledFixture: ComponentFixture<DisabledHostComponent>;
    let disabledHost: DisabledHostComponent;

    beforeEach(async () => {
      // TestBed is already configured by the outer beforeEach — create fixture only.
      disabledFixture = TestBed.createComponent(DisabledHostComponent);
      disabledHost = disabledFixture.componentInstance;
      await disabledFixture.whenStable();
    });

    it('should disable the disabled segment button', () => {
      const betaBtn = disabledFixture.nativeElement.querySelector(
        '[data-testid="segmented-b"]',
      ) as HTMLButtonElement;
      expect(betaBtn).toBeTruthy();
      expect(betaBtn.disabled).toBe(true);
    });

    it('should not change active when a disabled segment is clicked', async () => {
      const betaBtn = disabledFixture.nativeElement.querySelector(
        '[data-testid="segmented-b"]',
      ) as HTMLButtonElement;
      betaBtn.click();
      await disabledFixture.whenStable();

      expect(disabledHost.active()).toBe('a');
    });
  });
});
