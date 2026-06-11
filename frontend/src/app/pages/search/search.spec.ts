import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { Title } from '@angular/platform-browser';
import { environment } from '../../../environments/environment';
import { SearchComponent } from './search';

describe('SearchComponent', () => {
  let component: SearchComponent;
  let fixture: ComponentFixture<SearchComponent>;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SearchComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(SearchComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should create without firing a search for an empty query', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
    httpTesting.expectNone((r) => r.url.includes('/api/search'));
  });

  it('should set the page meta and search JSON-LD on init', () => {
    fixture.detectChanges();

    const title = TestBed.inject(Title).getTitle();
    expect(title).toBe(`Search | ${environment.siteName}`);

    const script = document.querySelector(
      'script[type="application/ld+json"][data-seo]',
    );
    expect(script).toBeTruthy();
    const jsonLd = JSON.parse(script!.textContent ?? '{}') as {
      '@type': string;
      url: string;
    };
    expect(jsonLd['@type']).toBe('SearchResultsPage');
    expect(jsonLd.url).toBe(`${environment.siteUrl}/search`);
  });

  it('should query /api/search when the search input receives text', async () => {
    fixture.detectChanges();

    const input = (fixture.nativeElement as HTMLElement).querySelector(
      '[data-testid="search-input"]',
    ) as HTMLInputElement;
    input.value = 'value semantics';
    input.dispatchEvent(new Event('input'));

    // The page debounces typing before issuing the request.
    await new Promise<void>((resolve) => setTimeout(resolve, 350));
    fixture.detectChanges();

    const emptyPage = {
      data: [],
      meta: { total: 0, page: 1, per_page: 12, total_pages: 0 },
    };

    // Typing also syncs the query into the URL, which re-emits the route
    // params and issues a second identical request — match them all.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    const requests = httpTesting.match(
      (r) => r.url.includes('/api/search') && r.method === 'GET',
    );
    expect(requests.length).toBeGreaterThan(0);
    for (const req of requests) {
      expect(req.request.params.get('q')).toBe('value semantics');
      req.flush(emptyPage);
    }
  });
});
