import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { HireComponent } from './hire';

describe('HireComponent', () => {
  let fixture: ComponentFixture<HireComponent>;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HireComponent],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(HireComponent);
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  });

  it('should render the studio headline as the single h1', () => {
    const h1s = el.querySelectorAll('h1');
    expect(h1s.length).toBe(1);
    expect(h1s[0].textContent).toContain('Work with me');
  });

  it('should render the two work lines as section headings', () => {
    const headings = Array.from(el.querySelectorAll('h2')).map((h) =>
      h.textContent?.trim(),
    );
    expect(headings).toContain('Agent and LLM systems');
    expect(headings).toContain('Go backend systems');
  });

  it('should carry the verbatim positioning and how-I-work copy', () => {
    expect(el.textContent).toContain(
      'I build and deliver backend and agent systems as a one-person studio',
    );
    expect(el.textContent).toContain(
      'be correct at 3am when no one is watching',
    );
    expect(el.textContent).toContain(
      'that is part of what you are hiring, not a nuisance',
    );
  });

  it('should list the real contact channels', () => {
    expect(
      el.querySelector('a[href="mailto:contact@koopa0.dev"]'),
    ).toBeTruthy();
    expect(
      el.querySelector(
        'a[href="https://www.linkedin.com/in/koopa-chen-70a4651ba/"]',
      ),
    ).toBeTruthy();
    expect(
      el.querySelector('a[href="https://github.com/koopa0"]'),
    ).toBeTruthy();
    expect(
      el.querySelector('a[href="https://x.com/Koopa012426"]'),
    ).toBeTruthy();
  });

  it('should link the koopa0.dev receipt to the writing', () => {
    const link = Array.from(el.querySelectorAll('a')).find(
      (a) => a.textContent?.trim() === 'koopa0.dev',
    );
    expect(link?.getAttribute('href')).toBe('/articles');
  });
});
