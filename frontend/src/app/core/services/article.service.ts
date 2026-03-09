import { Injectable, signal, computed, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, throwError, map, catchError } from 'rxjs';
import {
  Article,
  ArticleListItem,
  ArticlesResponse,
  ArticleFilters,
  CreateArticleRequest,
  UpdateArticleRequest,
  ArticleStatus,
} from '../models';
import { MOCK_ARTICLES, MOCK_ARTICLE_LIST_ITEMS } from './mock-data';

const CONTENT_BASE_URL = '/content/articles';
const WORDS_PER_MINUTE = 200;
const DEFAULT_PAGE_SIZE = 10;
const MOCK_DELAY_MS = 800;
const MOCK_WRITE_DELAY_MS = 1000;

@Injectable({
  providedIn: 'root',
})
export class ArticleService {
  private readonly http = inject(HttpClient);

  private articles = signal<Article[]>(MOCK_ARTICLES);
  private isLoading = signal(false);
  private error = signal<string | null>(null);

  readonly articleList = this.articles.asReadonly();
  readonly loading = this.isLoading.asReadonly();
  readonly errorMessage = this.error.asReadonly();

  readonly publishedArticles = computed(() =>
    this.articles().filter(
      (article) => article.status === ArticleStatus.PUBLISHED,
    ),
  );

  readonly latestArticles = computed(() =>
    this.publishedArticles()
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime())
      .slice(0, 6),
  );

  readonly popularArticles = computed(() =>
    this.publishedArticles()
      .sort((a, b) => b.viewCount - a.viewCount)
      .slice(0, 5),
  );

  getArticles(filters?: ArticleFilters): Observable<ArticlesResponse> {
    this.isLoading.set(true);
    this.error.set(null);

    return new Observable((observer) => {
      setTimeout(() => {
        try {
          let filteredArticles: ArticleListItem[] = [...MOCK_ARTICLE_LIST_ITEMS];

          if (filters?.tags?.length) {
            filteredArticles = filteredArticles.filter((article) =>
              filters.tags!.some((tag) => article.tags.includes(tag)),
            );
          }

          if (filters?.search) {
            const searchTerm = filters.search.toLowerCase();
            filteredArticles = filteredArticles.filter(
              (article) =>
                article.title.toLowerCase().includes(searchTerm) ||
                article.excerpt.toLowerCase().includes(searchTerm),
            );
          }

          if (filters?.status) {
            const fullArticles = MOCK_ARTICLES.filter(
              (article) => article.status === filters.status,
            );
            filteredArticles = filteredArticles.filter((item) =>
              fullArticles.some((article) => article.id === item.id),
            );
          }

          const sortBy = filters?.sortBy || 'publishedAt';
          const sortOrder = filters?.sortOrder || 'desc';

          filteredArticles.sort((a, b) => {
            let aValue: number | string;
            let bValue: number | string;

            switch (sortBy) {
              case 'publishedAt':
                aValue = a.publishedAt.getTime();
                bValue = b.publishedAt.getTime();
                break;
              case 'viewCount':
                aValue = a.viewCount;
                bValue = b.viewCount;
                break;
              case 'title':
                aValue = a.title.toLowerCase();
                bValue = b.title.toLowerCase();
                break;
              default:
                aValue = a.publishedAt.getTime();
                bValue = b.publishedAt.getTime();
            }

            if (sortOrder === 'asc') {
              return aValue > bValue ? 1 : -1;
            } else {
              return aValue < bValue ? 1 : -1;
            }
          });

          const page = filters?.page || 1;
          const limit = filters?.limit || DEFAULT_PAGE_SIZE;
          const startIndex = (page - 1) * limit;
          const endIndex = startIndex + limit;

          const paginatedArticles = filteredArticles.slice(
            startIndex,
            endIndex,
          );
          const total = filteredArticles.length;

          const response: ArticlesResponse = {
            articles: paginatedArticles,
            total,
            page,
            limit,
            hasNext: endIndex < total,
            hasPrevious: page > 1,
          };

          this.isLoading.set(false);
          observer.next(response);
          observer.complete();
        } catch (err) {
          this.isLoading.set(false);
          this.error.set('載入文章列表失敗');
          observer.error(err);
        }
      }, MOCK_DELAY_MS);
    });
  }

  getArticleById(id: string): Observable<Article> {
    this.isLoading.set(true);
    this.error.set(null);

    const article = MOCK_ARTICLES.find((a) => a.id === id);

    if (!article) {
      this.isLoading.set(false);
      this.error.set('文章不存在');
      return throwError(() => new Error('Article not found'));
    }

    this.incrementViewCount(article.id);

    return this.loadArticleContent(article);
  }

  getArticleBySlug(slug: string): Observable<Article> {
    this.isLoading.set(true);
    this.error.set(null);

    const article = MOCK_ARTICLES.find((a) => a.slug === slug);

    if (!article) {
      this.isLoading.set(false);
      this.error.set('文章不存在');
      return throwError(() => new Error('Article not found'));
    }

    this.incrementViewCount(article.id);

    return this.loadArticleContent(article);
  }

  private incrementViewCount(articleId: string): void {
    this.articles.update((articles) =>
      articles.map((a) =>
        a.id === articleId ? { ...a, viewCount: a.viewCount + 1 } : a,
      ),
    );
  }

  createArticle(request: CreateArticleRequest): Observable<Article> {
    this.isLoading.set(true);
    this.error.set(null);

    return new Observable((observer) => {
      setTimeout(() => {
        try {
          const newArticle: Article = {
            id: Date.now().toString(),
            title: request.title,
            slug: this.generateSlug(request.title),
            excerpt: request.excerpt,
            content: request.content,
            coverImage: request.coverImage,
            tags: request.tags,
            publishedAt: new Date(),
            updatedAt: new Date(),
            readingTime: this.calculateReadingTime(request.content),
            viewCount: 0,
            status: request.status,
            seoDescription: request.seoDescription,
            seoKeywords: request.seoKeywords,
          };

          this.articles.update((articles) => [...articles, newArticle]);
          this.isLoading.set(false);

          observer.next(newArticle);
          observer.complete();
        } catch (err) {
          this.isLoading.set(false);
          this.error.set('創建文章失敗');
          observer.error(err);
        }
      }, MOCK_WRITE_DELAY_MS);
    });
  }

  updateArticle(request: UpdateArticleRequest): Observable<Article> {
    this.isLoading.set(true);
    this.error.set(null);

    return new Observable((observer) => {
      setTimeout(() => {
        try {
          const articleIndex = this.articles().findIndex(
            (a) => a.id === request.id,
          );

          if (articleIndex === -1) {
            throw new Error('Article not found');
          }

          const currentArticle = this.articles()[articleIndex];
          const updatedArticle: Article = {
            ...currentArticle,
            ...request,
            updatedAt: new Date(),
            readingTime: request.content
              ? this.calculateReadingTime(request.content)
              : currentArticle.readingTime,
            slug: request.title
              ? this.generateSlug(request.title)
              : currentArticle.slug,
          };

          this.articles.update((articles) =>
            articles.map((article) =>
              article.id === request.id ? updatedArticle : article,
            ),
          );

          this.isLoading.set(false);
          observer.next(updatedArticle);
          observer.complete();
        } catch (err) {
          this.isLoading.set(false);
          this.error.set('更新文章失敗');
          observer.error(err);
        }
      }, MOCK_WRITE_DELAY_MS);
    });
  }

  deleteArticle(id: string): Observable<void> {
    this.isLoading.set(true);
    this.error.set(null);

    return new Observable((observer) => {
      setTimeout(() => {
        try {
          const articleExists = this.articles().some((a) => a.id === id);

          if (!articleExists) {
            throw new Error('Article not found');
          }

          this.articles.update((articles) =>
            articles.filter((a) => a.id !== id),
          );
          this.isLoading.set(false);

          observer.next();
          observer.complete();
        } catch (err) {
          this.isLoading.set(false);
          this.error.set('刪除文章失敗');
          observer.error(err);
        }
      }, MOCK_DELAY_MS);
    });
  }

  getArticlesBySeries(seriesId: string): Article[] {
    return this.publishedArticles()
      .filter((a) => a.seriesId === seriesId)
      .sort((a, b) => (a.seriesOrder ?? 0) - (b.seriesOrder ?? 0));
  }

  getRelatedArticles(articleId: string, limit = 3): ArticleListItem[] {
    const article = this.articles().find((a) => a.id === articleId);
    if (!article) {
      return [];
    }

    return this.publishedArticles()
      .filter((a) => a.id !== articleId)
      .map((a) => ({
        article: a,
        score: a.tags.filter((tag) => article.tags.includes(tag)).length,
      }))
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map((item) => ({
        id: item.article.id,
        title: item.article.title,
        slug: item.article.slug,
        excerpt: item.article.excerpt,
        coverImage: item.article.coverImage,
        tags: item.article.tags,
        publishedAt: item.article.publishedAt,
        readingTime: item.article.readingTime,
        viewCount: item.article.viewCount,
        seriesId: item.article.seriesId,
        seriesOrder: item.article.seriesOrder,
      }));
  }

  private loadArticleContent(article: Article): Observable<Article> {
    // 如果已有內容（如 admin 新建的文章），直接回傳
    if (article.content) {
      this.isLoading.set(false);
      return of(article);
    }

    // 從 .md 檔案載入內容
    return this.http
      .get(`${CONTENT_BASE_URL}/${article.slug}.md`, {
        responseType: 'text',
      })
      .pipe(
        map((content) => {
          this.isLoading.set(false);
          return { ...article, content };
        }),
        catchError(() => {
          this.isLoading.set(false);
          this.error.set('載入文章內容失敗');
          return throwError(() => new Error('Failed to load article content'));
        }),
      );
  }

  private generateSlug(title: string): string {
    return title
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .trim();
  }

  private calculateReadingTime(content: string): number {
    const wordCount = content.split(' ').length;
    return Math.ceil(wordCount / WORDS_PER_MINUTE);
  }
}
