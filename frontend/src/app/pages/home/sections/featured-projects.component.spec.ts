import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FeaturedProjectsComponent } from './featured-projects.component';

describe('FeaturedProjectsComponent', () => {
  let component: FeaturedProjectsComponent;
  let fixture: ComponentFixture<FeaturedProjectsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FeaturedProjectsComponent],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(FeaturedProjectsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display featured projects', () => {
    const projects = component['projects']();
    expect(projects.length).toBeGreaterThan(0);
  });

  it('should render section heading', () => {
    const h2 = fixture.nativeElement.querySelector('h2');
    expect(h2).not.toBeNull();
    expect(h2.textContent).toContain('Featured Projects');
  });

  it('should return correct status label', () => {
    expect(component['getStatusLabel']('completed')).toBe('Completed');
    expect(component['getStatusLabel']('in-progress')).toBe('In Progress');
    expect(component['getStatusLabel']('maintained')).toBe('Maintained');
  });

  it('should return correct status CSS class', () => {
    const completedClass = component['getStatusClass']('completed');
    expect(completedClass).toContain('emerald');

    const inProgressClass = component['getStatusClass']('in-progress');
    expect(inProgressClass).toContain('amber');

    const maintainedClass = component['getStatusClass']('maintained');
    expect(maintainedClass).toContain('sky');
  });
});
