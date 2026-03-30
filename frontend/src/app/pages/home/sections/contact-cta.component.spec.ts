import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ContactCtaComponent } from './contact-cta.component';

describe('ContactCtaComponent', () => {
  let component: ContactCtaComponent;
  let fixture: ComponentFixture<ContactCtaComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ContactCtaComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(ContactCtaComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should have four social links', () => {
    expect(component['socialLinks'].length).toBe(4);
  });

  it('should include Email link', () => {
    const email = component['socialLinks'].find((l) => l.name === 'Email');
    expect(email).toBeDefined();
    expect(email?.url).toContain('mailto:');
  });

  it('should include GitHub link', () => {
    const github = component['socialLinks'].find((l) => l.name === 'GitHub');
    expect(github).toBeDefined();
    expect(github?.url).toContain('github.com');
  });

  it('should render section heading', () => {
    const h2 = fixture.nativeElement.querySelector('h2');
    expect(h2).not.toBeNull();
    expect(h2.textContent).toContain('Have a Backend Challenge?');
  });

  it('should render all social link buttons', () => {
    const links = fixture.nativeElement.querySelectorAll('a');
    expect(links.length).toBe(4);
  });

  it('should have noopener noreferrer on external links', () => {
    const links = fixture.nativeElement.querySelectorAll('a');
    links.forEach((link: HTMLAnchorElement) => {
      expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    });
  });
});
