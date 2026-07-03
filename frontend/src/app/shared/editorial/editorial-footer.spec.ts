import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { EditorialFooterComponent } from './editorial-footer';

describe('EditorialFooterComponent', () => {
  let fixture: ComponentFixture<EditorialFooterComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EditorialFooterComponent],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(EditorialFooterComponent);
    fixture.detectChanges();
  });

  it('should render the wordmark and the copyright', () => {
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('koopa0.dev');
    expect(el.textContent).toContain('© 2026');
  });

  it('should link to the RSS feed', () => {
    const el = fixture.nativeElement as HTMLElement;
    const rss = Array.from(el.querySelectorAll('a')).find(
      (a) => a.textContent?.trim() === 'RSS',
    );
    expect(rss?.getAttribute('href')).toBe('/feed.xml');
  });

  it('should link to the hire page', () => {
    const el = fixture.nativeElement as HTMLElement;
    const hire = Array.from(el.querySelectorAll('a')).find(
      (a) => a.textContent?.trim() === 'Hire',
    );
    expect(hire?.getAttribute('href')).toBe('/hire');
  });
});
