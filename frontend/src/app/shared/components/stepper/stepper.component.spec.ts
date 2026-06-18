import { ComponentFixture, TestBed } from '@angular/core/testing';
import { StepperComponent, type StepItem } from './stepper.component';

const STEPS: StepItem[] = [
  { label: 'Account' },
  { label: 'Profile' },
  { label: 'Review' },
];

describe('StepperComponent', () => {
  let fixture: ComponentFixture<StepperComponent>;
  let component: StepperComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [StepperComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(StepperComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should render the data-testid="stepper" container', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.detectChanges();
    const ol = fixture.nativeElement.querySelector('[data-testid="stepper"]');
    expect(ol).toBeTruthy();
    expect(ol.tagName.toLowerCase()).toBe('ol');
  });

  it('should render a dot for each step', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.detectChanges();
    const dots = fixture.nativeElement.querySelectorAll(
      '[data-testid^="stepper-dot-"]',
    );
    expect(dots.length).toBe(STEPS.length);
  });

  it('should render step labels', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent as string;
    expect(text).toContain('Account');
    expect(text).toContain('Profile');
    expect(text).toContain('Review');
  });

  it('should mark the first dot as aria-current="step" when current is 0', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.componentRef.setInput('current', 0);
    fixture.detectChanges();

    const dot0 = fixture.nativeElement.querySelector(
      '[data-testid="stepper-dot-0"]',
    );
    expect(dot0.getAttribute('aria-current')).toBe('step');
  });

  it('should mark only the current dot as aria-current="step"', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.componentRef.setInput('current', 1);
    fixture.detectChanges();

    const dot0 = fixture.nativeElement.querySelector(
      '[data-testid="stepper-dot-0"]',
    );
    const dot1 = fixture.nativeElement.querySelector(
      '[data-testid="stepper-dot-1"]',
    );
    const dot2 = fixture.nativeElement.querySelector(
      '[data-testid="stepper-dot-2"]',
    );

    expect(dot0.getAttribute('aria-current')).toBeNull();
    expect(dot1.getAttribute('aria-current')).toBe('step');
    expect(dot2.getAttribute('aria-current')).toBeNull();
  });

  it('should show a checkmark svg in done steps and numbers in upcoming steps', () => {
    // current=1 → step 0 is done, step 1 is current, step 2 is upcoming
    fixture.componentRef.setInput('steps', STEPS);
    fixture.componentRef.setInput('current', 1);
    fixture.detectChanges();

    const dot0 = fixture.nativeElement.querySelector(
      '[data-testid="stepper-dot-0"]',
    ) as HTMLElement;
    const dot2 = fixture.nativeElement.querySelector(
      '[data-testid="stepper-dot-2"]',
    ) as HTMLElement;

    // done step should contain the check SVG, not a plain number
    expect(dot0.querySelector('svg')).toBeTruthy();
    // upcoming step should show a number (3 for index 2)
    expect(dot2.textContent?.trim()).toBe('3');
  });

  it('should not render a checkmark for the current step', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.componentRef.setInput('current', 1);
    fixture.detectChanges();

    const dot1 = fixture.nativeElement.querySelector(
      '[data-testid="stepper-dot-1"]',
    ) as HTMLElement;
    expect(dot1.querySelector('svg')).toBeNull();
    expect(dot1.textContent?.trim()).toBe('2');
  });

  it('should update aria-current when current input changes', () => {
    fixture.componentRef.setInput('steps', STEPS);
    fixture.componentRef.setInput('current', 0);
    fixture.detectChanges();

    expect(
      fixture.nativeElement
        .querySelector('[data-testid="stepper-dot-0"]')
        ?.getAttribute('aria-current'),
    ).toBe('step');

    fixture.componentRef.setInput('current', 2);
    fixture.detectChanges();

    expect(
      fixture.nativeElement
        .querySelector('[data-testid="stepper-dot-0"]')
        ?.getAttribute('aria-current'),
    ).toBeNull();
    expect(
      fixture.nativeElement
        .querySelector('[data-testid="stepper-dot-2"]')
        ?.getAttribute('aria-current'),
    ).toBe('step');
  });
});
