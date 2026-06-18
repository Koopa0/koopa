import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SeparatorComponent } from './separator.component';

describe('SeparatorComponent', () => {
  let fixture: ComponentFixture<SeparatorComponent>;
  let component: SeparatorComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SeparatorComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(SeparatorComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should render a data-testid="separator" element', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement.querySelector('[data-testid="separator"]');
    expect(el).toBeTruthy();
  });

  describe('horizontal (default)', () => {
    it('should have role="separator" and aria-orientation="horizontal" when no label', () => {
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      expect(el.getAttribute('role')).toBe('separator');
      expect(el.getAttribute('aria-orientation')).toBe('horizontal');
    });

    it('should apply the horizontal line class when orientation is "h"', () => {
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      expect(el.className).toContain('h-px');
      expect(el.className).toContain('w-full');
    });

    it('should NOT apply vertical class when orientation is "h"', () => {
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      expect(el.className).not.toContain('self-stretch');
    });
  });

  describe('vertical orientation', () => {
    it('should have aria-orientation="vertical" when orientation is "v"', () => {
      fixture.componentRef.setInput('orientation', 'v');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      expect(el.getAttribute('aria-orientation')).toBe('vertical');
    });

    it('should apply the vertical class when orientation is "v"', () => {
      fixture.componentRef.setInput('orientation', 'v');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      expect(el.className).toContain('w-px');
      expect(el.className).toContain('self-stretch');
    });
  });

  describe('label (horizontal only)', () => {
    it('should render the label text when label is provided', () => {
      fixture.componentRef.setInput('label', 'OR');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      expect(el.textContent).toContain('OR');
    });

    it('should set aria-label to the label value when label is provided', () => {
      fixture.componentRef.setInput('label', 'OR');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      expect(el.getAttribute('aria-label')).toBe('OR');
    });

    it('should render two decorative spans flanking the label', () => {
      fixture.componentRef.setInput('label', 'OR');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      const decorativeSpans = el.querySelectorAll('[aria-hidden="true"]');
      expect(decorativeSpans.length).toBe(2);
    });

    it('should NOT render the labelled variant when label is null', () => {
      fixture.detectChanges();
      // Without a label the separator is a plain div — no flanking spans
      const el = fixture.nativeElement.querySelector(
        '[data-testid="separator"]',
      ) as HTMLElement;
      const decorativeSpans = el.querySelectorAll('[aria-hidden="true"]');
      expect(decorativeSpans.length).toBe(0);
    });
  });
});
