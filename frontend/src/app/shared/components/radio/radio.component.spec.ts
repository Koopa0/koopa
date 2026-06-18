import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RadioComponent } from './radio.component';

// RadioComponent uses ng-content for its label and requires value + name inputs.
// Use a host component with multiple radios sharing the same groupValue model.

@Component({
  imports: [RadioComponent],
  template: `
    <app-radio
      name="fruit"
      value="apple"
      [(groupValue)]="selected"
      [disabled]="isDisabled()"
      testId="radio-apple"
    >
      Apple
    </app-radio>
    <app-radio
      name="fruit"
      value="banana"
      [(groupValue)]="selected"
      testId="radio-banana"
    >
      Banana
    </app-radio>
  `,
  standalone: true,
})
class HostRadioComponent {
  readonly selected = signal('');
  readonly isDisabled = signal(false);
}

describe('RadioComponent', () => {
  let hostFixture: ComponentFixture<HostRadioComponent>;
  let host: HostRadioComponent;

  function appleInput(): HTMLInputElement {
    return hostFixture.nativeElement.querySelector(
      '[data-testid="radio-apple"]',
    ) as HTMLInputElement;
  }

  function bananaInput(): HTMLInputElement {
    return hostFixture.nativeElement.querySelector(
      '[data-testid="radio-banana"]',
    ) as HTMLInputElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostRadioComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostRadioComponent);
    host = hostFixture.componentInstance;
    await hostFixture.whenStable();
  });

  it('should create both radio elements', () => {
    expect(appleInput()).toBeTruthy();
    expect(bananaInput()).toBeTruthy();
  });

  describe('groupValue model', () => {
    it('should render both radios as unchecked when groupValue is empty', () => {
      expect(appleInput().checked).toBe(false);
      expect(bananaInput().checked).toBe(false);
    });

    it('should render apple radio as checked when groupValue is apple', async () => {
      host.selected.set('apple');
      await hostFixture.whenStable();
      expect(appleInput().checked).toBe(true);
      expect(bananaInput().checked).toBe(false);
    });

    it('should render banana radio as checked when groupValue is banana', async () => {
      host.selected.set('banana');
      await hostFixture.whenStable();
      expect(bananaInput().checked).toBe(true);
      expect(appleInput().checked).toBe(false);
    });

    it('should update groupValue to apple when apple radio fires change event', async () => {
      appleInput().dispatchEvent(new Event('change'));
      await hostFixture.whenStable();
      expect(host.selected()).toBe('apple');
    });

    it('should update groupValue to banana when banana radio fires change event', async () => {
      host.selected.set('apple');
      await hostFixture.whenStable();
      bananaInput().dispatchEvent(new Event('change'));
      await hostFixture.whenStable();
      expect(host.selected()).toBe('banana');
    });

    it('should switch selection from apple to banana when banana change event fires', async () => {
      host.selected.set('apple');
      await hostFixture.whenStable();
      bananaInput().dispatchEvent(new Event('change'));
      await hostFixture.whenStable();
      expect(host.selected()).toBe('banana');
    });
  });

  describe('name input', () => {
    it('should set the name attribute on the native input', () => {
      expect(appleInput().name).toBe('fruit');
      expect(bananaInput().name).toBe('fruit');
    });
  });

  describe('value input', () => {
    it('should set the value attribute on the native input', () => {
      expect(appleInput().value).toBe('apple');
      expect(bananaInput().value).toBe('banana');
    });
  });

  describe('disabled input', () => {
    it('should not be disabled by default', () => {
      expect(appleInput().disabled).toBe(false);
    });

    it('should disable the native input when disabled is true', async () => {
      host.isDisabled.set(true);
      await hostFixture.whenStable();
      expect(appleInput().disabled).toBe(true);
    });

    it('should not affect banana radio when only apple is disabled', async () => {
      host.isDisabled.set(true);
      await hostFixture.whenStable();
      expect(bananaInput().disabled).toBe(false);
    });
  });

  describe('content projection', () => {
    it('should render projected label text inside each label element', () => {
      const labels = hostFixture.nativeElement.querySelectorAll(
        'label',
      ) as NodeListOf<HTMLLabelElement>;
      const texts = Array.from(labels).map((l) => l.textContent?.trim());
      expect(texts).toContain('Apple');
      expect(texts).toContain('Banana');
    });
  });

  describe('label wrapping', () => {
    it('should wrap each input inside its label for implicit association', () => {
      const labels = hostFixture.nativeElement.querySelectorAll(
        'label',
      ) as NodeListOf<HTMLLabelElement>;
      expect(labels[0].contains(appleInput())).toBe(true);
      expect(labels[1].contains(bananaInput())).toBe(true);
    });
  });

  describe('input type', () => {
    it('should render inputs with type radio', () => {
      expect(appleInput().type).toBe('radio');
      expect(bananaInput().type).toBe('radio');
    });
  });
});
