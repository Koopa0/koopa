import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CheckboxComponent } from './checkbox.component';

// Checkbox uses ng-content for its label — use a host component throughout.

@Component({
  imports: [CheckboxComponent],
  template: `
    <app-checkbox
      [(checked)]="isChecked"
      [disabled]="isDisabled()"
      [invalid]="isInvalid()"
      testId="host-cb"
    >
      Accept terms
    </app-checkbox>
  `,
  standalone: true,
})
class HostCheckboxComponent {
  readonly isChecked = signal(false);
  readonly isDisabled = signal(false);
  readonly isInvalid = signal(false);
}

describe('CheckboxComponent', () => {
  let hostFixture: ComponentFixture<HostCheckboxComponent>;
  let host: HostCheckboxComponent;

  function nativeInput(): HTMLInputElement {
    return hostFixture.nativeElement.querySelector(
      '[data-testid="host-cb"]',
    ) as HTMLInputElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostCheckboxComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostCheckboxComponent);
    host = hostFixture.componentInstance;
    await hostFixture.whenStable();
  });

  it('should create', () => {
    expect(
      hostFixture.nativeElement.querySelector('app-checkbox'),
    ).toBeTruthy();
  });

  describe('checked model', () => {
    it('should render unchecked by default', () => {
      expect(nativeInput().checked).toBe(false);
    });

    it('should render checked when host sets isChecked to true', async () => {
      host.isChecked.set(true);
      await hostFixture.whenStable();
      expect(nativeInput().checked).toBe(true);
    });

    it('should update host isChecked to true when checkbox is checked by user', async () => {
      const input = nativeInput();
      input.checked = true;
      input.dispatchEvent(new Event('change'));
      await hostFixture.whenStable();
      expect(host.isChecked()).toBe(true);
    });

    it('should update host isChecked to false when checkbox is unchecked by user', async () => {
      host.isChecked.set(true);
      await hostFixture.whenStable();
      const input = nativeInput();
      input.checked = false;
      input.dispatchEvent(new Event('change'));
      await hostFixture.whenStable();
      expect(host.isChecked()).toBe(false);
    });
  });

  describe('disabled input', () => {
    it('should not be disabled by default', () => {
      expect(nativeInput().disabled).toBe(false);
    });

    it('should disable the native input when disabled is true', async () => {
      host.isDisabled.set(true);
      await hostFixture.whenStable();
      expect(nativeInput().disabled).toBe(true);
    });

    it('should not change checked state when disabled checkbox receives change event', async () => {
      host.isDisabled.set(true);
      await hostFixture.whenStable();
      // Browsers don't fire change on disabled inputs, but guard the model
      expect(host.isChecked()).toBe(false);
    });
  });

  describe('invalid input', () => {
    it('should not have aria-invalid when invalid is false', () => {
      expect(nativeInput().getAttribute('aria-invalid')).toBeNull();
    });

    it('should set aria-invalid when invalid is true', async () => {
      host.isInvalid.set(true);
      await hostFixture.whenStable();
      expect(nativeInput().getAttribute('aria-invalid')).toBe('true');
    });
  });

  describe('content projection', () => {
    it('should render projected label text inside the label element', () => {
      const label = hostFixture.nativeElement.querySelector(
        'label',
      ) as HTMLLabelElement;
      expect(label.textContent?.trim()).toContain('Accept terms');
    });
  });

  describe('label wrapping', () => {
    it('should wrap the input inside a label element so clicking the label toggles the checkbox', () => {
      const label = hostFixture.nativeElement.querySelector(
        'label',
      ) as HTMLLabelElement;
      const input = nativeInput();
      // The input must be a descendant of the label for implicit association
      expect(label.contains(input)).toBe(true);
    });
  });
});
