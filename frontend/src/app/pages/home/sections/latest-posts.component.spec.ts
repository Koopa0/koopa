import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { LatestPostsComponent } from './latest-posts.component';

describe('LatestPostsComponent', () => {
  let component: LatestPostsComponent;
  let fixture: ComponentFixture<LatestPostsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LatestPostsComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LatestPostsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display latest articles', () => {
    const articles = component['latestArticles']();
    expect(articles.length).toBeGreaterThan(0);
  });

  it('should render section heading', () => {
    const h2 = fixture.nativeElement.querySelector('h2');
    expect(h2).not.toBeNull();
    expect(h2.textContent).toContain('Latest from the Blog');
  });

  it('should render View All Articles link', () => {
    const links = fixture.nativeElement.querySelectorAll('a');
    const viewAllLink = Array.from(links).find((a: unknown) =>
      (a as HTMLElement).textContent?.includes('View All Articles'),
    );
    expect(viewAllLink).toBeTruthy();
  });
});
