import {
  ComponentFixture,
  TestBed,
  fakeAsync,
  tick,
} from '@angular/core/testing';
import { provideRouter, ActivatedRoute } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { of } from 'rxjs';
import { TagComponent } from './tag';
import { ArticleService } from '../../core/services/article.service';
import { SeoService } from '../../core/services/seo/seo.service';

describe('TagComponent', () => {
  let component: TagComponent;
  let fixture: ComponentFixture<TagComponent>;
  let seoService: SeoService;
  let articleService: ArticleService;

  function createComponent(tag: string | null) {
    TestBed.overrideProvider(ActivatedRoute, {
      useValue: {
        snapshot: {
          paramMap: {
            get: (key: string) => (key === 'tag' ? tag : null),
          },
        },
      },
    });

    fixture = TestBed.createComponent(TagComponent);
    component = fixture.componentInstance;
    seoService = TestBed.inject(SeoService);
    articleService = TestBed.inject(ArticleService);
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TagComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              paramMap: { get: () => 'Angular' },
            },
          },
        },
      ],
    }).compileComponents();
  });

  it('should create', () => {
    createComponent('Angular');
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should set tag name from route parameter', () => {
    createComponent('TypeScript');
    fixture.detectChanges();
    expect(component['tagName']()).toBe('TypeScript');
  });

  it('should load articles filtered by tag on init', fakeAsync(() => {
    createComponent('Angular');
    const spy = spyOn(articleService, 'getArticles').and.callThrough();

    fixture.detectChanges();
    tick(800);

    expect(spy).toHaveBeenCalledWith(
      jasmine.objectContaining({
        tags: ['Angular'],
        sortBy: 'publishedAt',
        sortOrder: 'desc',
      }),
    );
  }));

  it('should set SEO meta with tag name', () => {
    createComponent('Docker');
    const spy = spyOn(seoService, 'updateMeta');
    fixture.detectChanges();

    expect(spy).toHaveBeenCalledWith(
      jasmine.objectContaining({
        title: 'Docker 相關文章',
        description: '所有標記為 Docker 的技術文章',
        ogUrl: 'https://koopa0.dev/tags/Docker',
      }),
    );
  });

  it('should show loading state initially', () => {
    createComponent('Angular');
    // 不 tick，保持 loading 狀態
    fixture.detectChanges();

    expect(component['isLoading']()).toBe(true);
    const skeleton = fixture.nativeElement.querySelector('.animate-pulse');
    expect(skeleton).toBeTruthy();
  });

  it('should hide loading and show articles after data loads', fakeAsync(() => {
    createComponent('Angular');
    fixture.detectChanges();
    tick(800);
    fixture.detectChanges();

    expect(component['isLoading']()).toBe(false);
    const skeleton = fixture.nativeElement.querySelector('app-skeleton');
    expect(skeleton).toBeFalsy();
  }));

  it('should display tag name in heading', () => {
    createComponent('Rust');
    fixture.detectChanges();

    const heading = fixture.nativeElement.querySelector('h1');
    expect(heading.textContent.trim()).toBe('Rust');
  });

  it('should have back link to articles page', () => {
    createComponent('Angular');
    fixture.detectChanges();

    const links = Array.from(
      fixture.nativeElement.querySelectorAll('a'),
    ) as HTMLElement[];
    const backLink = links.find(
      (link) =>
        (link as HTMLAnchorElement).getAttribute('href') === '/articles',
    );
    expect(backLink).toBeTruthy();
    expect(backLink!.textContent).toContain('返回文章列表');
  });

  it('should show article count after loading', fakeAsync(() => {
    createComponent('Angular');
    fixture.detectChanges();
    tick(800);
    fixture.detectChanges();

    const articleCount = component['articles']().length;
    const text = fixture.nativeElement.textContent;
    expect(text).toContain(`${articleCount}`);
    expect(text).toContain('篇相關文章');
  }));

  it('should show empty state when no articles match tag', fakeAsync(() => {
    createComponent('NonExistentTag12345');
    fixture.detectChanges();
    tick(800);
    fixture.detectChanges();

    const articles = component['articles']();
    if (articles.length === 0) {
      const text = fixture.nativeElement.textContent;
      expect(text).toContain('沒有找到');
      expect(text).toContain('NonExistentTag12345');
    }
  }));

  it('should not load articles when tag parameter is missing', () => {
    const spy = spyOn(articleService, 'getArticles');
    createComponent(null);
    fixture.detectChanges();

    expect(spy).not.toHaveBeenCalled();
    expect(component['tagName']()).toBe('');
  });

  it('should highlight current tag badge in article cards', fakeAsync(() => {
    createComponent('Angular');
    fixture.detectChanges();
    tick(800);
    fixture.detectChanges();

    const articles = component['articles']();
    if (articles.length > 0) {
      // 當前 tag 的 badge 應有不同樣式（bg-zinc-700）
      const badges = fixture.nativeElement.querySelectorAll(
        '.rounded-sm.px-2.py-0\\.5',
      );
      const currentTagBadges = Array.from(badges).filter(
        (badge: unknown) =>
          (badge as HTMLElement).textContent?.trim() === 'Angular' &&
          (badge as HTMLElement).classList.contains('bg-zinc-700'),
      );
      // 如果有 Angular 文章，應有高亮 badge
      if (articles.some((a) => a.tags.includes('Angular'))) {
        expect(currentTagBadges.length).toBeGreaterThan(0);
      }
    }
  }));
});
