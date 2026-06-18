import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SelectComponent, SelectOption } from './select.component';

const MOCK_OPTIONS: SelectOption[] = [
  { value: 'apple', label: 'Apple' },
  { value: 'banana', label: 'Banana' },
  { value: 'cherry', label: 'Cherry' },
];

describe('SelectComponent', () => {
  let fixture: ComponentFixture<SelectComponent>;
  let component: SelectComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SelectComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(SelectComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('options', MOCK_OPTIONS);
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('options rendering', () => {
    it('should render one option element per option when options are provided', () => {
      const optionEls = fixture.nativeElement.querySelectorAll(
        'option',
      ) as NodeListOf<HTMLOptionElement>;
      expect(optionEls.length).toBe(3);
    });

    it('should render option labels as text content', () => {
      const optionEls = Array.from(
        fixture.nativeElement.querySelectorAll(
          'option',
        ) as NodeListOf<HTMLOptionElement>,
      );
      const labels = optionEls.map((o) => o.textContent?.trim());
      expect(labels).toContain('Apple');
      expect(labels).toContain('Banana');
      expect(labels).toContain('Cherry');
    });

    it('should render option values correctly', () => {
      const optionEls = Array.from(
        fixture.nativeElement.querySelectorAll(
          'option',
        ) as NodeListOf<HTMLOptionElement>,
      );
      const values = optionEls.map((o) => o.value);
      expect(values).toContain('apple');
      expect(values).toContain('banana');
      expect(values).toContain('cherry');
    });
  });

  describe('placeholder input', () => {
    it('should not render a placeholder option when placeholder is not set', () => {
      const optionEls = fixture.nativeElement.querySelectorAll(
        'option',
      ) as NodeListOf<HTMLOptionElement>;
      expect(optionEls.length).toBe(3);
    });

    it('should render a disabled placeholder option when placeholder is provided', () => {
      fixture.componentRef.setInput('placeholder', 'Choose a fruit');
      fixture.detectChanges();
      const optionEls = fixture.nativeElement.querySelectorAll(
        'option',
      ) as NodeListOf<HTMLOptionElement>;
      // placeholder + 3 real options
      expect(optionEls.length).toBe(4);
      const placeholder = optionEls[0];
      expect(placeholder.disabled).toBe(true);
      expect(placeholder.textContent?.trim()).toBe('Choose a fruit');
    });
  });

  describe('value model', () => {
    it('should reflect set value on the native select when value is set', () => {
      fixture.componentRef.setInput('value', 'banana');
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.value).toBe('banana');
    });

    it('should update value model when user changes selection', () => {
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      select.value = 'cherry';
      select.dispatchEvent(new Event('change'));
      expect(component.value()).toBe('cherry');
    });
  });

  describe('disabled input', () => {
    it('should not be disabled by default', () => {
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.disabled).toBe(false);
    });

    it('should disable the native select when disabled is true', () => {
      fixture.componentRef.setInput('disabled', true);
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.disabled).toBe(true);
    });
  });

  describe('invalid input', () => {
    it('should not have aria-invalid when invalid is false', () => {
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.getAttribute('aria-invalid')).toBeNull();
    });

    it('should set aria-invalid when invalid is true', () => {
      fixture.componentRef.setInput('invalid', true);
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.getAttribute('aria-invalid')).toBe('true');
    });
  });

  describe('ariaLabel input', () => {
    it('should not set aria-label when ariaLabel is null and no placeholder', () => {
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.getAttribute('aria-label')).toBeNull();
    });

    it('should set aria-label when ariaLabel is provided', () => {
      fixture.componentRef.setInput('ariaLabel', 'Fruit selector');
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.getAttribute('aria-label')).toBe('Fruit selector');
    });

    it('should fall back to placeholder as aria-label when ariaLabel is null', () => {
      fixture.componentRef.setInput('placeholder', 'Pick one');
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.getAttribute('aria-label')).toBe('Pick one');
    });
  });

  describe('testId input', () => {
    it('should not set data-testid when testId is null', () => {
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.getAttribute('data-testid')).toBeNull();
    });

    it('should set data-testid when testId is provided', () => {
      fixture.componentRef.setInput('testId', 'fruit-select');
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        '[data-testid="fruit-select"]',
      );
      expect(select).toBeTruthy();
    });
  });

  describe('size input', () => {
    it('should apply md size classes by default', () => {
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.className).toContain('pl-2.5');
      expect(select.className).toContain('py-2');
    });

    it('should apply sm size classes when size is sm', () => {
      fixture.componentRef.setInput('size', 'sm');
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.className).toContain('pl-2');
      expect(select.className).toContain('py-1.5');
    });

    it('should apply lg size classes when size is lg', () => {
      fixture.componentRef.setInput('size', 'lg');
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector(
        'select',
      ) as HTMLSelectElement;
      expect(select.className).toContain('pl-3');
      expect(select.className).toContain('py-2.5');
    });
  });
});

// Host-based integration test for two-way model binding
@Component({
  imports: [SelectComponent],
  template: `<app-select
    [(value)]="fruit"
    [options]="opts"
    testId="host-select"
  />`,
  standalone: true,
})
class HostSelectComponent {
  fruit = 'apple';
  readonly opts: SelectOption[] = MOCK_OPTIONS;
}

describe('SelectComponent (host integration)', () => {
  let hostFixture: ComponentFixture<HostSelectComponent>;
  let host: HostSelectComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostSelectComponent],
    }).compileComponents();

    hostFixture = TestBed.createComponent(HostSelectComponent);
    host = hostFixture.componentInstance;
    hostFixture.detectChanges();
  });

  it('should reflect host value on the native select via two-way binding', () => {
    const select = hostFixture.nativeElement.querySelector(
      '[data-testid="host-select"]',
    ) as HTMLSelectElement;
    expect(select.value).toBe('apple');
  });

  it('should update host property when native change event fires', () => {
    const select = hostFixture.nativeElement.querySelector(
      '[data-testid="host-select"]',
    ) as HTMLSelectElement;
    select.value = 'cherry';
    select.dispatchEvent(new Event('change'));
    expect(host.fruit).toBe('cherry');
  });
});
