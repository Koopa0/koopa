import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ArticleService } from './article.service';
import { ArticleStatus } from '../models';

describe('ArticleService', () => {
  let service: ArticleService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ArticleService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should have published articles computed', () => {
    const published = service.publishedArticles();
    expect(published.length).toBeGreaterThan(0);
    expect(published.every((a) => a.status === ArticleStatus.PUBLISHED)).toBe(
      true,
    );
  });

  it('should have latest articles sorted by date descending', () => {
    const latest = service.latestArticles();
    expect(latest.length).toBeGreaterThan(0);
    expect(latest.length).toBeLessThanOrEqual(6);

    for (let i = 1; i < latest.length; i++) {
      expect(latest[i].publishedAt.getTime()).toBeLessThanOrEqual(
        latest[i - 1].publishedAt.getTime(),
      );
    }
  });

  it('should have popular articles sorted by view count descending', () => {
    const popular = service.popularArticles();
    expect(popular.length).toBeGreaterThan(0);

    for (let i = 1; i < popular.length; i++) {
      expect(popular[i].viewCount).toBeLessThanOrEqual(
        popular[i - 1].viewCount,
      );
    }
  });

  it('should get paginated articles', fakeAsync(() => {
    let response: unknown;
    service.getArticles({ page: 1, limit: 3 }).subscribe((r) => {
      response = r;
    });
    tick(1000);

    expect(response).toBeDefined();
    expect(
      (response as { articles: unknown[] }).articles.length,
    ).toBeLessThanOrEqual(3);
  }));

  it('should filter articles by tags', fakeAsync(() => {
    let response: unknown;
    service.getArticles({ tags: ['Angular'] }).subscribe((r) => {
      response = r;
    });
    tick(1000);

    expect(response).toBeDefined();
    const articles = (response as { articles: { tags: string[] }[] }).articles;
    expect(articles.every((a) => a.tags.includes('Angular'))).toBe(true);
  }));

  it('should get article by slug and load content from .md', fakeAsync(() => {
    const slug = 'angular-signals-complete-guide';
    let article: unknown;
    service.getArticleBySlug(slug).subscribe((a) => {
      article = a;
    });

    const req = httpMock.expectOne(`/content/articles/${slug}.md`);
    expect(req.request.method).toBe('GET');
    req.flush('# Test Content');

    expect(article).toBeDefined();
    expect((article as { content: string }).content).toBe('# Test Content');
  }));

  it('should return error for non-existent slug', () => {
    let errorCaught = false;
    service.getArticleBySlug('non-existent').subscribe({
      error: () => {
        errorCaught = true;
      },
    });
    expect(errorCaught).toBe(true);
  });

  it('should create a new article', fakeAsync(() => {
    let created: unknown;
    service
      .createArticle({
        title: 'New Article',
        excerpt: 'Test excerpt',
        content: 'Test content',
        tags: ['Test'],
        status: ArticleStatus.DRAFT,
      })
      .subscribe((a) => {
        created = a;
      });
    tick(1500);

    expect(created).toBeDefined();
    expect((created as { title: string }).title).toBe('New Article');
  }));

  it('should delete an article', fakeAsync(() => {
    const initialCount = service.articleList().length;
    let completed = false;
    service.deleteArticle('1').subscribe(() => {
      completed = true;
    });
    tick(1000);

    expect(completed).toBe(true);
    expect(service.articleList().length).toBe(initialCount - 1);
  }));
});
