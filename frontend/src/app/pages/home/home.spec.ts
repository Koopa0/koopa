import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { HomeComponent } from './home';
import { SeoService } from '../../core/services/seo/seo.service';

describe('HomeComponent', () => {
  let component: HomeComponent;
  let fixture: ComponentFixture<HomeComponent>;
  let seoService: SeoService;

  beforeEach(async () => {
    // @defer (on viewport) requires IntersectionObserver, which jsdom lacks
    if (!globalThis.IntersectionObserver) {
      globalThis.IntersectionObserver = class IntersectionObserver {
        constructor(private callback: IntersectionObserverCallback) {}
        observe(): void {
          /* noop */
        }
        unobserve(): void {
          /* noop */
        }
        disconnect(): void {
          /* noop */
        }
        takeRecords(): IntersectionObserverEntry[] {
          return [];
        }
        readonly root = null;
        readonly rootMargin = '';
        readonly thresholds: readonly number[] = [];
      } as unknown as typeof globalThis.IntersectionObserver;
    }

    await TestBed.configureTestingModule({
      imports: [HomeComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    seoService = TestBed.inject(SeoService);
    vi.spyOn(seoService, 'updateMeta');

    fixture = TestBed.createComponent(HomeComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should call SeoService.updateMeta on init with Home title', () => {
    expect(seoService.updateMeta).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Home',
        description: expect.stringContaining('Koopa'),
      }),
    );
  });

  it('should render hero section immediately (deferred sections load on viewport)', () => {
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('app-hero-section')).toBeTruthy();
  });
});
