import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { EditorialMastheadComponent } from './editorial-masthead';

describe('EditorialMastheadComponent', () => {
  let fixture: ComponentFixture<EditorialMastheadComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EditorialMastheadComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(EditorialMastheadComponent);
  });

  it('should render the serif wordmark', async () => {
    await fixture.whenStable();
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.ed-wordmark')?.textContent).toContain('koopa');
  });

  it('should mark "articles" active on the front-door route', async () => {
    await TestBed.inject(Router).navigateByUrl('/');
    await fixture.whenStable();
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const links = Array.from(el.querySelectorAll('.ed-nav a'));
    // articles / topics / about.
    expect(links.length).toBe(3);
    const articles = links.find((a) => a.textContent?.includes('articles'));
    expect(articles?.getAttribute('data-active')).toBe('true');
    const topics = links.find((a) => a.textContent?.includes('topics'));
    expect(topics?.getAttribute('data-active')).toBe('false');
  });
});
