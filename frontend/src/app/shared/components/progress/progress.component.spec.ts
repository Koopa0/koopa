import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ProgressComponent } from './progress.component';

describe('ProgressComponent', () => {
  let fixture: ComponentFixture<ProgressComponent>;
  let component: ProgressComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProgressComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(ProgressComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.componentRef.setInput('value', 50);
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  describe('ARIA progressbar contract', () => {
    it('should render an element with role progressbar', () => {
      fixture.componentRef.setInput('value', 40);
      fixture.detectChanges();

      const bar = fixture.nativeElement.querySelector(
        '[role="progressbar"]',
      ) as HTMLElement;
      expect(bar).toBeTruthy();
    });

    it('should set aria-valuenow to the clamped value', () => {
      fixture.componentRef.setInput('value', 75);
      fixture.detectChanges();

      const bar = fixture.nativeElement.querySelector(
        '[role="progressbar"]',
      ) as HTMLElement;
      expect(bar.getAttribute('aria-valuenow')).toBe('75');
    });

    it('should set aria-valuemin to 0 and aria-valuemax to 100', () => {
      fixture.componentRef.setInput('value', 50);
      fixture.detectChanges();

      const bar = fixture.nativeElement.querySelector(
        '[role="progressbar"]',
      ) as HTMLElement;
      expect(bar.getAttribute('aria-valuemin')).toBe('0');
      expect(bar.getAttribute('aria-valuemax')).toBe('100');
    });

    it('should use default aria-label "Progress" when label input is null', () => {
      fixture.componentRef.setInput('value', 30);
      fixture.componentRef.setInput('label', null);
      fixture.detectChanges();

      const bar = fixture.nativeElement.querySelector(
        '[role="progressbar"]',
      ) as HTMLElement;
      expect(bar.getAttribute('aria-label')).toBe('Progress');
    });

    it('should use provided label for aria-label when label input is set', () => {
      fixture.componentRef.setInput('value', 60);
      fixture.componentRef.setInput('label', 'Upload progress');
      fixture.detectChanges();

      const bar = fixture.nativeElement.querySelector(
        '[role="progressbar"]',
      ) as HTMLElement;
      expect(bar.getAttribute('aria-label')).toBe('Upload progress');
    });
  });

  describe('value clamping', () => {
    it('should clamp value to 0 when value input is negative', () => {
      fixture.componentRef.setInput('value', -10);
      fixture.detectChanges();

      expect(component['clamped']()).toBe(0);
      const bar = fixture.nativeElement.querySelector(
        '[role="progressbar"]',
      ) as HTMLElement;
      expect(bar.getAttribute('aria-valuenow')).toBe('0');
    });

    it('should clamp value to 100 when value input exceeds 100', () => {
      fixture.componentRef.setInput('value', 150);
      fixture.detectChanges();

      expect(component['clamped']()).toBe(100);
      const bar = fixture.nativeElement.querySelector(
        '[role="progressbar"]',
      ) as HTMLElement;
      expect(bar.getAttribute('aria-valuenow')).toBe('100');
    });

    it('should pass through value unchanged when value is within 0-100', () => {
      fixture.componentRef.setInput('value', 42);
      fixture.detectChanges();

      expect(component['clamped']()).toBe(42);
    });
  });

  describe('fill width', () => {
    it('should set fill div width to 60% when value is 60', () => {
      fixture.componentRef.setInput('value', 60);
      fixture.detectChanges();

      const fill = fixture.nativeElement.querySelector(
        '[role="progressbar"] div',
      ) as HTMLElement;
      expect(fill.style.width).toBe('60%');
    });

    it('should set fill div width to 0% when value is clamped to 0', () => {
      fixture.componentRef.setInput('value', -5);
      fixture.detectChanges();

      const fill = fixture.nativeElement.querySelector(
        '[role="progressbar"] div',
      ) as HTMLElement;
      expect(fill.style.width).toBe('0%');
    });

    it('should set fill div width to 100% when value is clamped to 100', () => {
      fixture.componentRef.setInput('value', 200);
      fixture.detectChanges();

      const fill = fixture.nativeElement.querySelector(
        '[role="progressbar"] div',
      ) as HTMLElement;
      expect(fill.style.width).toBe('100%');
    });
  });

  describe('tone classes', () => {
    it('should apply bg-brand fill class when tone is brand', () => {
      fixture.componentRef.setInput('value', 50);
      fixture.componentRef.setInput('tone', 'brand');
      fixture.detectChanges();

      const fill = fixture.nativeElement.querySelector(
        '[role="progressbar"] div',
      ) as HTMLElement;
      expect(fill.className).toContain('bg-brand');
    });

    it('should apply bg-success fill class when tone is success', () => {
      fixture.componentRef.setInput('value', 50);
      fixture.componentRef.setInput('tone', 'success');
      fixture.detectChanges();

      const fill = fixture.nativeElement.querySelector(
        '[role="progressbar"] div',
      ) as HTMLElement;
      expect(fill.className).toContain('bg-success');
    });

    it('should apply bg-warn fill class when tone is warn', () => {
      fixture.componentRef.setInput('value', 50);
      fixture.componentRef.setInput('tone', 'warn');
      fixture.detectChanges();

      const fill = fixture.nativeElement.querySelector(
        '[role="progressbar"] div',
      ) as HTMLElement;
      expect(fill.className).toContain('bg-warn');
    });

    it('should default tone to brand when tone input is not provided', () => {
      fixture.componentRef.setInput('value', 50);
      fixture.detectChanges();

      expect(component.tone()).toBe('brand');
      const fill = fixture.nativeElement.querySelector(
        '[role="progressbar"] div',
      ) as HTMLElement;
      expect(fill.className).toContain('bg-brand');
    });
  });

  describe('testId', () => {
    it('should set data-testid on the progressbar element when testId is provided', () => {
      fixture.componentRef.setInput('value', 70);
      fixture.componentRef.setInput('testId', 'upload-progress');
      fixture.detectChanges();

      const el = fixture.nativeElement.querySelector(
        '[data-testid="upload-progress"]',
      );
      expect(el).toBeTruthy();
    });

    it('should not render data-testid when testId is null', () => {
      fixture.componentRef.setInput('value', 70);
      fixture.componentRef.setInput('testId', null);
      fixture.detectChanges();

      const el = fixture.nativeElement.querySelector('[data-testid]');
      expect(el).toBeNull();
    });
  });
});
