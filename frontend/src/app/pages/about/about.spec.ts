import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { AboutComponent } from './about';

describe('AboutComponent', () => {
  let fixture: ComponentFixture<AboutComponent>;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AboutComponent],
      providers: [provideNoopAnimations()],
    }).compileComponents();

    fixture = TestBed.createComponent(AboutComponent);
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  });

  it('should render the statement headline as the single h1', () => {
    const h1s = el.querySelectorAll('h1');
    expect(h1s.length).toBe(1);
    expect(h1s[0].textContent).toContain('I build systems');
  });

  it('should render the prose, pull line, and NOW copy', () => {
    expect(el.textContent).toContain('personal knowledge engine');
    expect(el.textContent).toContain('less a blog than a system I run on myself');
    expect(el.textContent).toContain('Going deeper on Go and Rust');
  });

  it('should list the real contact links', () => {
    expect(el.querySelector('a[href="https://github.com/koopa0"]')).toBeTruthy();
    expect(
      el.querySelector(
        'a[href="https://www.linkedin.com/in/koopa-chen-70a4651ba/"]',
      ),
    ).toBeTruthy();
    expect(el.querySelector('a[href="https://x.com/Koopa012426"]')).toBeTruthy();
    expect(
      el.querySelector('a[href="mailto:contact@koopa0.dev"]'),
    ).toBeTruthy();
  });

  it('should render the dated NOW liveness stamp', () => {
    expect(el.textContent).toContain('Updated June 25, 2026');
  });

  it('should render the colophon stack and signature', () => {
    expect(el.textContent).toContain('Go · PostgreSQL · pgvector');
    expect(el.textContent).toContain('Written & maintained by one person.');
  });

  it('should carry the shared pure-CSS rise orchestration on each block', () => {
    // statement, seam, prose, emphasis, now, colophon, elsewhere — seven blocks,
    // each revealed by the shared `.ed-rise` keyframes (no JS observer).
    expect(el.querySelectorAll('.ed-rise').length).toBe(7);
  });
});
