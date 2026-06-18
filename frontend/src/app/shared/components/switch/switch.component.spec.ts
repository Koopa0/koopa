import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SwitchComponent } from './switch.component';

// SwitchComponent uses ng-content for its label — use a host component throughout.
// isOn is a WritableSignal so Angular's twoWayBindingSet wires [(checked)] correctly
// in zoneless mode. isDisabled is called explicitly in the [disabled] binding.

@Component({
  imports: [SwitchComponent],
  template: `
    <app-switch
      [(checked)]="isOn"
      [disabled]="isDisabled()"
      testId="host-switch"
    >
      Enable notifications
    </app-switch>
  `,
  standalone: true,
})
class HostSwitchComponent {
  readonly isOn = signal(false);
  readonly isDisabled = signal(false);
}

describe('SwitchComponent', () => {
  let hostFixture: ComponentFixture<HostSwitchComponent>;
  let host: HostSwitchComponent;

  function switchButton(): HTMLButtonElement {
    return hostFixture.nativeElement.querySelector(
      '[data-testid="host-switch"]',
    ) as HTMLButtonElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostSwitchComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostSwitchComponent);
    host = hostFixture.componentInstance;
    await hostFixture.whenStable();
  });

  it('should create', () => {
    expect(switchButton()).toBeTruthy();
  });

  describe('role and ARIA', () => {
    it('should have role="switch" on the button element', () => {
      expect(switchButton().getAttribute('role')).toBe('switch');
    });

    it('should have aria-checked="false" when checked is false', () => {
      expect(switchButton().getAttribute('aria-checked')).toBe('false');
    });

    it('should have aria-checked="true" when checked is true', async () => {
      host.isOn.set(true);
      await hostFixture.whenStable();
      expect(switchButton().getAttribute('aria-checked')).toBe('true');
    });
  });

  describe('checked model', () => {
    it('should render unchecked by default', () => {
      expect(host.isOn()).toBe(false);
    });

    it('should toggle checked to true when button is clicked while unchecked', async () => {
      switchButton().click();
      await hostFixture.whenStable();
      expect(host.isOn()).toBe(true);
    });

    it('should toggle checked back to false when button is clicked while checked', async () => {
      host.isOn.set(true);
      await hostFixture.whenStable();
      switchButton().click();
      await hostFixture.whenStable();
      expect(host.isOn()).toBe(false);
    });

    it('should reflect host value in aria-checked after toggle', async () => {
      switchButton().click();
      await hostFixture.whenStable();
      expect(switchButton().getAttribute('aria-checked')).toBe('true');
    });
  });

  describe('disabled input', () => {
    it('should not be disabled by default', () => {
      expect(switchButton().disabled).toBe(false);
    });

    it('should disable the button when disabled is true', async () => {
      host.isDisabled.set(true);
      await hostFixture.whenStable();
      expect(switchButton().disabled).toBe(true);
    });

    it('should not toggle checked when button is disabled and clicked', async () => {
      host.isDisabled.set(true);
      await hostFixture.whenStable();
      switchButton().click();
      await hostFixture.whenStable();
      expect(host.isOn()).toBe(false);
    });
  });

  describe('track visual state', () => {
    it('should apply the off-state track classes when unchecked', () => {
      const track = switchButton().querySelector('span') as HTMLSpanElement;
      expect(track.className).toContain('bg-overlay');
    });

    it('should apply the on-state track classes when checked', async () => {
      host.isOn.set(true);
      await hostFixture.whenStable();
      const track = switchButton().querySelector('span') as HTMLSpanElement;
      expect(track.className).toContain('bg-brand');
    });
  });

  describe('content projection', () => {
    it('should render projected label text inside the button element', () => {
      expect(switchButton().textContent?.trim()).toContain(
        'Enable notifications',
      );
    });
  });

  describe('button type', () => {
    it('should have type="button" to prevent accidental form submission', () => {
      expect(switchButton().type).toBe('button');
    });
  });
});
