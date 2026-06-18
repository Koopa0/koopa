import { ComponentFixture, TestBed } from '@angular/core/testing';
import { StatCardComponent } from './stat-card.component';

describe('StatCardComponent', () => {
  let fixture: ComponentFixture<StatCardComponent>;
  let component: StatCardComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [StatCardComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(StatCardComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.componentRef.setInput('label', 'Revenue');
    fixture.componentRef.setInput('value', '1,234');
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  describe('label and value rendering', () => {
    it('should display the label when label input is provided', () => {
      fixture.componentRef.setInput('label', 'Total Orders');
      fixture.componentRef.setInput('value', '42');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain('Total Orders');
    });

    it('should display a string value when value input is a string', () => {
      fixture.componentRef.setInput('label', 'Revenue');
      fixture.componentRef.setInput('value', '$9,999');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain('$9,999');
    });

    it('should display a numeric value when value input is a number', () => {
      fixture.componentRef.setInput('label', 'Active Users');
      fixture.componentRef.setInput('value', 512);
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain('512');
    });
  });

  describe('delta rendering', () => {
    it('should not render delta element when delta input is null', () => {
      fixture.componentRef.setInput('label', 'Metric');
      fixture.componentRef.setInput('value', '100');
      fixture.componentRef.setInput('delta', null);
      fixture.detectChanges();

      // No delta spans beyond label and value
      const spans = (fixture.nativeElement as HTMLElement).querySelectorAll(
        'span',
      );
      // Only label span and value span should exist
      expect(spans.length).toBe(2);
    });

    it('should render delta text when delta input is provided', () => {
      fixture.componentRef.setInput('label', 'Revenue');
      fixture.componentRef.setInput('value', '1,000');
      fixture.componentRef.setInput('delta', '+12%');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain('+12%');
    });

    it('should not render delta text when delta transitions from value to null', () => {
      fixture.componentRef.setInput('label', 'Revenue');
      fixture.componentRef.setInput('value', '1,000');
      fixture.componentRef.setInput('delta', '+12%');
      fixture.detectChanges();

      fixture.componentRef.setInput('delta', null);
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).not.toContain('+12%');
    });
  });

  describe('trend colour classes', () => {
    it('should apply text-success class when trend is up', () => {
      fixture.componentRef.setInput('label', 'Sales');
      fixture.componentRef.setInput('value', '200');
      fixture.componentRef.setInput('delta', '+5%');
      fixture.componentRef.setInput('trend', 'up');
      fixture.detectChanges();

      const deltaSpan = (fixture.nativeElement as HTMLElement).querySelectorAll(
        'span',
      )[2];
      expect(deltaSpan.className).toContain('text-success');
    });

    it('should apply text-error class when trend is down', () => {
      fixture.componentRef.setInput('label', 'Churn');
      fixture.componentRef.setInput('value', '80');
      fixture.componentRef.setInput('delta', '-3%');
      fixture.componentRef.setInput('trend', 'down');
      fixture.detectChanges();

      const deltaSpan = (fixture.nativeElement as HTMLElement).querySelectorAll(
        'span',
      )[2];
      expect(deltaSpan.className).toContain('text-error');
    });

    it('should apply text-fg-subtle class when trend is flat', () => {
      fixture.componentRef.setInput('label', 'Visits');
      fixture.componentRef.setInput('value', '500');
      fixture.componentRef.setInput('delta', '0%');
      fixture.componentRef.setInput('trend', 'flat');
      fixture.detectChanges();

      const deltaSpan = (fixture.nativeElement as HTMLElement).querySelectorAll(
        'span',
      )[2];
      expect(deltaSpan.className).toContain('text-fg-subtle');
    });

    it('should default trend to flat when trend input is not provided', () => {
      fixture.componentRef.setInput('label', 'Visits');
      fixture.componentRef.setInput('value', '500');
      fixture.componentRef.setInput('delta', 'stable');
      fixture.detectChanges();

      expect(component.trend()).toBe('flat');
      const deltaSpan = (fixture.nativeElement as HTMLElement).querySelectorAll(
        'span',
      )[2];
      expect(deltaSpan.className).toContain('text-fg-subtle');
    });
  });

  describe('testId', () => {
    it('should set data-testid attribute when testId input is provided', () => {
      fixture.componentRef.setInput('label', 'MRR');
      fixture.componentRef.setInput('value', '$4,200');
      fixture.componentRef.setInput('testId', 'mrr-card');
      fixture.detectChanges();

      const container = (fixture.nativeElement as HTMLElement).querySelector(
        '[data-testid="mrr-card"]',
      );
      expect(container).toBeTruthy();
    });

    it('should not render data-testid when testId input is null', () => {
      fixture.componentRef.setInput('label', 'MRR');
      fixture.componentRef.setInput('value', '$4,200');
      fixture.componentRef.setInput('testId', null);
      fixture.detectChanges();

      const container = (fixture.nativeElement as HTMLElement).querySelector(
        '[data-testid]',
      );
      expect(container).toBeNull();
    });
  });
});
