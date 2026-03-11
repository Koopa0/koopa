import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { HeroSectionComponent } from './hero-section.component';

describe('HeroSectionComponent', () => {
  let component: HeroSectionComponent;
  let fixture: ComponentFixture<HeroSectionComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HeroSectionComponent],
      providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
    }).compileComponents();

    fixture = TestBed.createComponent(HeroSectionComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render hero heading', () => {
    const h1 = fixture.nativeElement.querySelector('h1');
    expect(h1).not.toBeNull();
    expect(h1.textContent).toContain('Building reliable');
  });

  it('should render role badge', () => {
    const badge = fixture.nativeElement.querySelector('p');
    expect(badge.textContent).toContain('Software Engineer');
  });

  it('should render View Projects CTA', () => {
    const buttons = fixture.nativeElement.querySelectorAll('button');
    const projectsCta = Array.from(buttons).find((btn: unknown) =>
      (btn as HTMLElement).textContent?.includes('View Projects'),
    );
    expect(projectsCta).toBeTruthy();
  });

  it('should render Get In Touch CTA', () => {
    const buttons = fixture.nativeElement.querySelectorAll('button');
    const contactCta = Array.from(buttons).find((btn: unknown) =>
      (btn as HTMLElement).textContent?.includes('Get In Touch'),
    );
    expect(contactCta).toBeTruthy();
  });
});
