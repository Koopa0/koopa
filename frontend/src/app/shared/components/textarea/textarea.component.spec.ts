import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TextareaComponent } from './textarea.component';

describe('TextareaComponent', () => {
  let fixture: ComponentFixture<TextareaComponent>;
  let component: TextareaComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TextareaComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(TextareaComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('value model', () => {
    it('should reflect initial empty value in the native textarea', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.value).toBe('');
    });

    it('should reflect set value in the native textarea when value is set', () => {
      fixture.componentRef.setInput('value', 'hello world');
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.value).toBe('hello world');
    });

    it('should update value model when user types into the textarea', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      ta.value = 'user typed';
      ta.dispatchEvent(new Event('input'));
      expect(component.value()).toBe('user typed');
    });
  });

  describe('placeholder input', () => {
    it('should render placeholder when placeholder input is set', () => {
      fixture.componentRef.setInput('placeholder', 'Describe your issue');
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.placeholder).toBe('Describe your issue');
    });
  });

  describe('disabled input', () => {
    it('should not be disabled by default', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.disabled).toBe(false);
    });

    it('should disable the native textarea when disabled is true', () => {
      fixture.componentRef.setInput('disabled', true);
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.disabled).toBe(true);
    });
  });

  describe('invalid input', () => {
    it('should not have aria-invalid when invalid is false', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.getAttribute('aria-invalid')).toBeNull();
    });

    it('should set aria-invalid when invalid is true', () => {
      fixture.componentRef.setInput('invalid', true);
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.getAttribute('aria-invalid')).toBe('true');
    });
  });

  describe('rows input', () => {
    it('should default to 3 rows', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.rows).toBe(3);
    });

    it('should render the specified number of rows when rows input is set', () => {
      fixture.componentRef.setInput('rows', 8);
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.rows).toBe(8);
    });
  });

  describe('testId input', () => {
    it('should not set data-testid attribute when testId is null', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.getAttribute('data-testid')).toBeNull();
    });

    it('should set data-testid attribute when testId is provided', () => {
      fixture.componentRef.setInput('testId', 'my-textarea');
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        '[data-testid="my-textarea"]',
      ) as HTMLTextAreaElement;
      expect(ta).toBeTruthy();
    });
  });

  describe('size input', () => {
    it('should apply md size classes by default', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.className).toContain('px-2.5');
      expect(ta.className).toContain('py-2');
    });

    it('should apply sm size classes when size is sm', () => {
      fixture.componentRef.setInput('size', 'sm');
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.className).toContain('px-2');
      expect(ta.className).toContain('py-1.5');
    });

    it('should apply lg size classes when size is lg', () => {
      fixture.componentRef.setInput('size', 'lg');
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.className).toContain('px-3');
      expect(ta.className).toContain('py-2.5');
    });
  });

  describe('mono input', () => {
    it('should apply font-sans class by default', () => {
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.className).toContain('font-sans');
    });

    it('should apply font-mono class when mono is true', () => {
      fixture.componentRef.setInput('mono', true);
      fixture.detectChanges();
      const ta = fixture.nativeElement.querySelector(
        'textarea',
      ) as HTMLTextAreaElement;
      expect(ta.className).toContain('font-mono');
      expect(ta.className).not.toContain('font-sans');
    });
  });
});

// Host-based integration test for two-way model binding
@Component({
  imports: [TextareaComponent],
  template: `<app-textarea [(value)]="notes" testId="host-ta" />`,
  standalone: true,
})
class HostTextareaComponent {
  notes = 'initial notes';
}

describe('TextareaComponent (host integration)', () => {
  let hostFixture: ComponentFixture<HostTextareaComponent>;
  let host: HostTextareaComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostTextareaComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostTextareaComponent);
    host = hostFixture.componentInstance;
    hostFixture.detectChanges();
  });

  it('should reflect host value in the native textarea via two-way binding', () => {
    const ta = hostFixture.nativeElement.querySelector(
      '[data-testid="host-ta"]',
    ) as HTMLTextAreaElement;
    expect(ta.value).toBe('initial notes');
  });

  it('should update host property when native input event fires', () => {
    const ta = hostFixture.nativeElement.querySelector(
      '[data-testid="host-ta"]',
    ) as HTMLTextAreaElement;
    ta.value = 'updated notes';
    ta.dispatchEvent(new Event('input'));
    expect(host.notes).toBe('updated notes');
  });
});
