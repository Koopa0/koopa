import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SpinnerComponent } from './spinner.component';

describe('SpinnerComponent', () => {
  let fixture: ComponentFixture<SpinnerComponent>;
  let component: SpinnerComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SpinnerComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(SpinnerComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should render the default data-testid="spinner" element', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement.querySelector('[data-testid="spinner"]');
    expect(el).toBeTruthy();
  });

  it('should have role="status" for accessibility', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement.querySelector('[data-testid="spinner"]');
    expect(el.getAttribute('role')).toBe('status');
  });

  it('should use "Loading" as the default aria-label', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement.querySelector('[data-testid="spinner"]');
    expect(el.getAttribute('aria-label')).toBe('Loading');
  });

  it('should apply a custom aria-label when label input is provided', () => {
    fixture.componentRef.setInput('label', 'Saving changes');
    fixture.detectChanges();
    const el = fixture.nativeElement.querySelector('[data-testid="spinner"]');
    expect(el.getAttribute('aria-label')).toBe('Saving changes');
  });

  describe('size input', () => {
    it('should apply the sm size class when size is "sm"', () => {
      fixture.componentRef.setInput('size', 'sm');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="spinner"]',
      ) as HTMLElement;
      expect(el.className).toContain('size-3.5');
    });

    it('should apply the md size class when size is "md" (default)', () => {
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="spinner"]',
      ) as HTMLElement;
      expect(el.className).toContain('size-[18px]');
    });

    it('should apply the lg size class when size is "lg"', () => {
      fixture.componentRef.setInput('size', 'lg');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="spinner"]',
      ) as HTMLElement;
      expect(el.className).toContain('size-[26px]');
    });

    it('should not apply sm class when size changes from sm to lg', () => {
      fixture.componentRef.setInput('size', 'sm');
      fixture.detectChanges();
      fixture.componentRef.setInput('size', 'lg');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="spinner"]',
      ) as HTMLElement;
      expect(el.className).not.toContain('size-3.5');
      expect(el.className).toContain('size-[26px]');
    });
  });

  describe('testId input', () => {
    it('should use a custom data-testid when testId is provided', () => {
      fixture.componentRef.setInput('testId', 'page-spinner');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector(
        '[data-testid="page-spinner"]',
      );
      expect(el).toBeTruthy();
      expect(el.getAttribute('role')).toBe('status');
    });

    it('should NOT render the default data-testid when a custom testId is set', () => {
      fixture.componentRef.setInput('testId', 'page-spinner');
      fixture.detectChanges();
      expect(
        fixture.nativeElement.querySelector('[data-testid="spinner"]'),
      ).toBeNull();
    });
  });
});
