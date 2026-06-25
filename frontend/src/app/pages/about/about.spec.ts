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

  it('should expose the four rail jump-links', () => {
    for (const id of ['statement', 'now', 'elsewhere', 'colophon']) {
      expect(el.querySelector(`a[href="#${id}"]`)).toBeTruthy();
    }
  });

  it('should list the real contact links', () => {
    expect(el.querySelector('a[href="https://github.com/koopa0"]')).toBeTruthy();
    expect(
      el.querySelector('a[href="mailto:contact@koopa0.dev"]'),
    ).toBeTruthy();
  });

  it('should render the dated NOW liveness stamp', () => {
    expect(el.textContent).toContain('Updated June 25, 2026');
  });

  it('should close with the colophon signature', () => {
    expect(el.textContent).toContain('Written & maintained by one person.');
  });

  it('should mark the in-view section active in the rail', () => {
    const statementLink = el.querySelector('a[href="#statement"]');
    expect(statementLink?.classList.contains('is-active')).toBe(true);
  });

  it('should wire the scroll-spy + reveal when IntersectionObserver exists', async () => {
    const callbacks: IntersectionObserverCallback[] = [];
    class FakeObserver {
      constructor(cb: IntersectionObserverCallback) {
        callbacks.push(cb);
      }
      observe(): void {
        /* no-op */
      }
      unobserve(): void {
        /* no-op */
      }
      disconnect(): void {
        /* no-op */
      }
    }
    vi.stubGlobal('IntersectionObserver', FakeObserver);
    vi.stubGlobal('matchMedia', () => ({ matches: false }));

    const fresh = TestBed.createComponent(AboutComponent);
    fresh.detectChanges();
    await fresh.whenStable();
    TestBed.tick();
    fresh.detectChanges();

    const freshEl = fresh.nativeElement as HTMLElement;
    // afterNextRender wired the observers (scroll-spy, then reveal).
    expect(callbacks.length).toBeGreaterThanOrEqual(1);
    // jsdom getBoundingClientRect() = 0 → the sync above-fold reveal shows blocks.
    expect(freshEl.querySelector('#now')?.classList.contains('is-in')).toBe(true);

    // Drive the scroll-spy (first observer) to the NOW section.
    const now = freshEl.querySelector('#now') as Element;
    callbacks[0](
      [{ isIntersecting: true, target: now } as IntersectionObserverEntry],
      {} as IntersectionObserver,
    );
    fresh.detectChanges();
    expect(
      freshEl.querySelector('a[href="#now"]')?.classList.contains('is-active'),
    ).toBe(true);

    vi.unstubAllGlobals();
  });
});
