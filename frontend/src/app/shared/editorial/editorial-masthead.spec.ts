import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { EditorialMastheadComponent } from './editorial-masthead';
import { CommandPaletteService } from '../command-palette/command-palette.service';

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

  it('should render the wordmark and letterhead signature', async () => {
    await fixture.whenStable();
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.ed-wordmark')?.textContent).toContain('koopa');
    expect(el.textContent).toContain('written & maintained by one person');
  });

  it('should mark Writing active on the home route', async () => {
    await TestBed.inject(Router).navigateByUrl('/');
    await fixture.whenStable();
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const links = Array.from(el.querySelectorAll('.ed-nav a'));
    const writing = links.find((a) => a.textContent?.includes('Writing'));
    expect(writing?.getAttribute('data-active')).toBe('true');
  });

  it('should open the command palette when search is clicked', async () => {
    await fixture.whenStable();
    fixture.detectChanges();

    const palette = TestBed.inject(CommandPaletteService);
    const search = (fixture.nativeElement as HTMLElement).querySelector(
      '[data-testid="ed-search"]',
    ) as HTMLButtonElement;
    search.click();

    expect(palette.isOpen()).toBe(true);
  });
});
