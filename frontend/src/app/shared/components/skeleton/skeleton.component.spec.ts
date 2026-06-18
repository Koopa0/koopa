import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SkeletonComponent } from './skeleton.component';

describe('SkeletonComponent', () => {
  let fixture: ComponentFixture<SkeletonComponent>;
  let component: SkeletonComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SkeletonComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(SkeletonComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  describe('aria-hidden', () => {
    it('should be aria-hidden true so screen readers skip the placeholder', () => {
      fixture.detectChanges();
      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.getAttribute('aria-hidden')).toBe('true');
    });
  });

  describe('variant classes', () => {
    it('should apply text variant classes when variant is text', () => {
      fixture.componentRef.setInput('variant', 'text');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('h-3');
      expect(span.className).toContain('w-full');
    });

    it('should apply title variant classes when variant is title', () => {
      fixture.componentRef.setInput('variant', 'title');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('h-5');
      expect(span.className).toContain('w-1/2');
    });

    it('should apply circle variant classes when variant is circle', () => {
      fixture.componentRef.setInput('variant', 'circle');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('rounded-full');
      expect(span.className).toContain('size-10');
    });

    it('should apply block variant classes when variant is block', () => {
      fixture.componentRef.setInput('variant', 'block');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('h-24');
      expect(span.className).toContain('w-full');
    });

    it('should default to text variant when variant input is not provided', () => {
      fixture.detectChanges();

      expect(component.variant()).toBe('text');
      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('h-3');
    });
  });

  describe('custom width and height', () => {
    it('should apply inline width style when width input is provided', () => {
      fixture.componentRef.setInput('width', '200px');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.style.width).toBe('200px');
    });

    it('should apply inline height style when height input is provided', () => {
      fixture.componentRef.setInput('height', '48px');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.style.height).toBe('48px');
    });

    it('should not apply inline width style when width is null', () => {
      fixture.componentRef.setInput('width', null);
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.style.width).toBe('');
    });

    it('should not apply inline height style when height is null', () => {
      fixture.componentRef.setInput('height', null);
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.style.height).toBe('');
    });
  });

  describe('testId', () => {
    it('should set data-testid when testId input is provided', () => {
      fixture.componentRef.setInput('testId', 'card-skeleton');
      fixture.detectChanges();

      const el = fixture.nativeElement.querySelector(
        '[data-testid="card-skeleton"]',
      );
      expect(el).toBeTruthy();
    });

    it('should not render data-testid when testId is null', () => {
      fixture.componentRef.setInput('testId', null);
      fixture.detectChanges();

      const el = fixture.nativeElement.querySelector('[data-testid]');
      expect(el).toBeNull();
    });
  });
});
