import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TechStackComponent } from './tech-stack.component';

describe('TechStackComponent', () => {
  let component: TechStackComponent;
  let fixture: ComponentFixture<TechStackComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TechStackComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(TechStackComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should have three tech categories', () => {
    expect(component['techCategories'].length).toBe(3);
  });

  it('should have Frontend category with Angular', () => {
    const frontend = component['techCategories'].find(
      (c) => c.name === 'Frontend',
    );
    expect(frontend).toBeDefined();
    expect(frontend?.items).toContain('Angular');
  });

  it('should have Backend category with Golang', () => {
    const backend = component['techCategories'].find(
      (c) => c.name === 'Backend',
    );
    expect(backend).toBeDefined();
    expect(backend?.items).toContain('Golang');
  });

  it('should have DevOps category', () => {
    const devops = component['techCategories'].find((c) => c.name === 'DevOps');
    expect(devops).toBeDefined();
    expect(devops?.items).toContain('Docker');
  });

  it('should render section heading', () => {
    const h2 = fixture.nativeElement.querySelector('h2');
    expect(h2).not.toBeNull();
    expect(h2.textContent).toContain('Tech Stack');
  });

  it('should render all category cards', () => {
    const cards = fixture.nativeElement.querySelectorAll('h3');
    expect(cards.length).toBe(3);
  });
});
