import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { InputComponent } from './input.component';

describe('InputComponent', () => {
  let fixture: ComponentFixture<InputComponent>;
  let component: InputComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [InputComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(InputComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('value model', () => {
    it('should reflect initial empty value in the native input', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.value).toBe('');
    });

    it('should reflect set value in the native input when value is set', () => {
      fixture.componentRef.setInput('value', 'hello');
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.value).toBe('hello');
    });

    it('should update value model when user types into the input', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      input.value = 'typed text';
      input.dispatchEvent(new Event('input'));
      expect(component.value()).toBe('typed text');
    });
  });

  describe('type input', () => {
    it('should render type="text" by default', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.type).toBe('text');
    });

    it('should render type="password" when type input is password', () => {
      fixture.componentRef.setInput('type', 'password');
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.type).toBe('password');
    });

    it('should render type="email" when type input is email', () => {
      fixture.componentRef.setInput('type', 'email');
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.type).toBe('email');
    });
  });

  describe('placeholder input', () => {
    it('should render placeholder when placeholder input is set', () => {
      fixture.componentRef.setInput('placeholder', 'Enter your name');
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.placeholder).toBe('Enter your name');
    });
  });

  describe('disabled input', () => {
    it('should not be disabled by default', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.disabled).toBe(false);
    });

    it('should disable the native input when disabled is true', () => {
      fixture.componentRef.setInput('disabled', true);
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.disabled).toBe(true);
    });
  });

  describe('invalid input', () => {
    it('should not have aria-invalid when invalid is false', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.getAttribute('aria-invalid')).toBeNull();
    });

    it('should set aria-invalid when invalid is true', () => {
      fixture.componentRef.setInput('invalid', true);
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.getAttribute('aria-invalid')).toBe('true');
    });
  });

  describe('testId input', () => {
    it('should not set data-testid attribute when testId is null', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.getAttribute('data-testid')).toBeNull();
    });

    it('should set data-testid attribute when testId is provided', () => {
      fixture.componentRef.setInput('testId', 'my-input');
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        '[data-testid="my-input"]',
      ) as HTMLInputElement;
      expect(input).toBeTruthy();
    });
  });

  describe('size input', () => {
    it('should apply md size classes by default', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.className).toContain('px-2.5');
      expect(input.className).toContain('py-2');
    });

    it('should apply sm size classes when size is sm', () => {
      fixture.componentRef.setInput('size', 'sm');
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.className).toContain('px-2');
      expect(input.className).toContain('py-1.5');
    });

    it('should apply lg size classes when size is lg', () => {
      fixture.componentRef.setInput('size', 'lg');
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.className).toContain('px-3');
      expect(input.className).toContain('py-2.5');
    });
  });

  describe('mono input', () => {
    it('should apply font-sans class by default', () => {
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.className).toContain('font-sans');
    });

    it('should apply font-mono class when mono is true', () => {
      fixture.componentRef.setInput('mono', true);
      fixture.detectChanges();
      const input = fixture.nativeElement.querySelector(
        'input',
      ) as HTMLInputElement;
      expect(input.className).toContain('font-mono');
      expect(input.className).not.toContain('font-sans');
    });
  });
});

// Host-based integration test for content projection & model two-way binding
@Component({
  imports: [InputComponent],
  template: `<app-input [(value)]="name" testId="host-input" />`,
  standalone: true,
})
class HostInputComponent {
  name = 'initial';
}

describe('InputComponent (host integration)', () => {
  let hostFixture: ComponentFixture<HostInputComponent>;
  let host: HostInputComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostInputComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostInputComponent);
    host = hostFixture.componentInstance;
    hostFixture.detectChanges();
  });

  it('should reflect host value in the native input via two-way binding', () => {
    const input = hostFixture.nativeElement.querySelector(
      '[data-testid="host-input"]',
    ) as HTMLInputElement;
    expect(input.value).toBe('initial');
  });

  it('should update host property when native input event fires', () => {
    const input = hostFixture.nativeElement.querySelector(
      '[data-testid="host-input"]',
    ) as HTMLInputElement;
    input.value = 'updated';
    input.dispatchEvent(new Event('input'));
    expect(host.name).toBe('updated');
  });
});
