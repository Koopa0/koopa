import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SkeletonComponent } from './skeleton.component';

describe('SkeletonComponent', () => {
  let component: SkeletonComponent;
  let fixture: ComponentFixture<SkeletonComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SkeletonComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(SkeletonComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render card variant by default', () => {
    const el = fixture.nativeElement as HTMLElement;
    const pulseElements = el.querySelectorAll('.animate-pulse');
    expect(pulseElements.length).toBeGreaterThan(0);

    // Card variant has border-t separator for meta row
    const borderT = el.querySelector('.border-t');
    expect(borderT).toBeTruthy();
  });

  it('should render text variant when set', () => {
    fixture.componentRef.setInput('variant', 'text');
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const spacey = el.querySelector('.space-y-3');
    expect(spacey).toBeTruthy();

    // Text variant: 3 lines
    const pulseElements = el.querySelectorAll('.animate-pulse');
    expect(pulseElements.length).toBe(3);
  });

  it('should render article variant when set', () => {
    fixture.componentRef.setInput('variant', 'article');
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const spacey = el.querySelector('.space-y-6');
    expect(spacey).toBeTruthy();

    // Article variant has a large title placeholder + meta + content lines
    const pulseElements = el.querySelectorAll('.animate-pulse');
    expect(pulseElements.length).toBeGreaterThan(5);
  });

  it('should use animate-pulse for loading animation', () => {
    const el = fixture.nativeElement as HTMLElement;
    const pulseElements = el.querySelectorAll('.animate-pulse');
    expect(pulseElements.length).toBeGreaterThan(0);
  });
});
