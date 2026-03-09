import { TestBed } from '@angular/core/testing';
import { SearchService } from './search.service';
import { Article, ArticleStatus } from '../models/article.model';

const MOCK_ARTICLE: Article = {
  id: '1',
  title: 'Angular Signals Guide',
  slug: 'angular-signals-guide',
  excerpt: 'Learn about Angular signals and reactive programming.',
  content:
    'Angular signals provide a reactive way to manage state in components.',
  tags: ['Angular', 'TypeScript'],
  publishedAt: new Date('2024-01-01'),
  updatedAt: new Date('2024-01-01'),
  readingTime: 10,
  viewCount: 100,
  status: ArticleStatus.PUBLISHED,
};

const MOCK_ARTICLE_2: Article = {
  id: '2',
  title: 'Golang Concurrency',
  slug: 'golang-concurrency',
  excerpt: 'Deep dive into goroutines and channels.',
  content: 'Go provides powerful concurrency primitives with goroutines.',
  tags: ['Golang'],
  publishedAt: new Date('2024-02-01'),
  updatedAt: new Date('2024-02-01'),
  readingTime: 15,
  viewCount: 80,
  status: ArticleStatus.PUBLISHED,
};

describe('SearchService', () => {
  let service: SearchService;
  const articles: Article[] = [MOCK_ARTICLE, MOCK_ARTICLE_2];

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(SearchService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should start with empty state', () => {
    expect(service.query()).toBe('');
    expect(service.results()).toEqual([]);
    expect(service.searching()).toBe(false);
    expect(service.hasResults()).toBe(false);
  });

  it('should find articles matching title', () => {
    service.search('Angular', articles);
    expect(service.hasResults()).toBe(true);
    expect(service.results().some((r) => r.article.id === '1')).toBe(true);
  });

  it('should find articles matching tags', () => {
    service.search('Golang', articles);
    expect(service.hasResults()).toBe(true);
    expect(service.results().some((r) => r.article.id === '2')).toBe(true);
  });

  it('should find articles matching content', () => {
    service.search('goroutines', articles);
    expect(service.hasResults()).toBe(true);
    expect(service.results()[0].article.id).toBe('2');
  });

  it('should return empty results for non-matching query', () => {
    service.search('xyznotfound', articles);
    expect(service.hasResults()).toBe(false);
    expect(service.results()).toEqual([]);
  });

  it('should set empty results for blank query', () => {
    service.search('Angular', articles);
    expect(service.hasResults()).toBe(true);

    service.search('', articles);
    expect(service.hasResults()).toBe(false);
  });

  it('should sort results by relevance score descending', () => {
    service.search('Angular', articles);
    const results = service.results();
    for (let i = 1; i < results.length; i++) {
      expect(results[i].score).toBeLessThanOrEqual(results[i - 1].score);
    }
  });

  it('should clear search state', () => {
    service.search('Angular', articles);
    expect(service.hasResults()).toBe(true);

    service.clearSearch();
    expect(service.query()).toBe('');
    expect(service.results()).toEqual([]);
  });

  it('should provide highlights for title matches', () => {
    service.search('Angular', articles);
    const result = service.results().find((r) => r.article.id === '1');
    expect(result?.highlights.title).toContain('<mark>');
  });

  it('should provide highlights for tag matches', () => {
    service.search('Golang', articles);
    const result = service.results().find((r) => r.article.id === '2');
    expect(result?.highlights.tags).toContain('Golang');
  });
});
