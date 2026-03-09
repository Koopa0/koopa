import { Injectable, signal, computed } from '@angular/core';
import { Article } from '../models/article.model';
import type { BuildLog } from '../models/build-log.model';
import type { TilEntry } from '../models/til.model';
import type { Note } from '../models/note.model';

export type SearchResultType = 'article' | 'build-log' | 'til' | 'note';

export interface SearchResult {
  article: Article;
  score: number;
  contentType?: SearchResultType;
  highlights: {
    title?: string;
    content?: string;
    tags?: string[];
  };
}

export interface UnifiedSearchResult {
  id: string;
  title: string;
  excerpt: string;
  slug: string;
  tags: string[];
  contentType: SearchResultType;
  score: number;
  publishedAt: Date;
}

@Injectable({
  providedIn: 'root'
})
export class SearchService {
  // Search state
  private searchQuery = signal('');
  private searchResults = signal<SearchResult[]>([]);
  private isSearching = signal(false);
  
  // Public observables
  query = this.searchQuery.asReadonly();
  results = this.searchResults.asReadonly();
  searching = this.isSearching.asReadonly();
  hasResults = computed(() => this.searchResults().length > 0);
  
  /**
   * Perform search across articles
   * Implements fuzzy matching and relevance scoring
   */
  search(query: string, articles: Article[]): void {
    this.searchQuery.set(query);
    
    if (!query.trim()) {
      this.searchResults.set([]);
      return;
    }
    
    this.isSearching.set(true);
    
    // Normalize query for case-insensitive search
    const normalizedQuery = query.toLowerCase().trim();
    const queryWords = normalizedQuery.split(/\s+/);
    
    const results: SearchResult[] = [];
    
    for (const article of articles) {
      let score = 0;
      const highlights: SearchResult['highlights'] = {};
      
      // Search in title (highest weight)
      const titleMatch = this.searchInText(article.title, queryWords);
      if (titleMatch.score > 0) {
        score += titleMatch.score * 3; // Title matches are 3x more important
        highlights.title = this.highlightText(article.title, queryWords);
      }
      
      // Search in content
      const contentMatch = this.searchInText(article.content, queryWords);
      if (contentMatch.score > 0) {
        score += contentMatch.score;
        highlights.content = this.extractHighlightedExcerpt(article.content, queryWords);
      }
      
      // Search in excerpt
      if (article.excerpt) {
        const excerptMatch = this.searchInText(article.excerpt, queryWords);
        if (excerptMatch.score > 0) {
          score += excerptMatch.score * 2; // Excerpt matches are 2x more important
        }
      }
      
      // Search in tags
      const matchingTags = article.tags.filter(tag => 
        queryWords.some(word => tag.toLowerCase().includes(word))
      );
      if (matchingTags.length > 0) {
        score += matchingTags.length * 2;
        highlights.tags = matchingTags;
      }
      
      // Add to results if score > 0
      if (score > 0) {
        results.push({ article, score, highlights });
      }
    }
    
    // Sort by relevance score (descending)
    results.sort((a, b) => b.score - a.score);
    
    this.searchResults.set(results);
    this.isSearching.set(false);
  }
  
  clearSearch(): void {
    this.searchQuery.set('');
    this.searchResults.set([]);
    this.unifiedResults.set([]);
  }

  private readonly unifiedResults = signal<UnifiedSearchResult[]>([]);
  readonly unified = this.unifiedResults.asReadonly();

  searchAll(
    query: string,
    articles: Article[],
    buildLogs: BuildLog[],
    tils: TilEntry[],
    notes: Note[],
  ): void {
    this.searchQuery.set(query);

    if (!query.trim()) {
      this.unifiedResults.set([]);
      return;
    }

    const normalizedQuery = query.toLowerCase().trim();
    const queryWords = normalizedQuery.split(/\s+/);
    const results: UnifiedSearchResult[] = [];

    for (const article of articles) {
      const score = this.scoreItem(article.title, article.content, article.tags, queryWords);
      if (score > 0) {
        results.push({
          id: article.id,
          title: article.title,
          excerpt: article.excerpt,
          slug: article.slug,
          tags: article.tags,
          contentType: 'article',
          score,
          publishedAt: article.publishedAt,
        });
      }
    }

    for (const bl of buildLogs) {
      const score = this.scoreItem(bl.title, bl.content, bl.tags, queryWords);
      if (score > 0) {
        results.push({
          id: bl.id,
          title: bl.title,
          excerpt: bl.excerpt,
          slug: bl.slug,
          tags: bl.tags,
          contentType: 'build-log',
          score,
          publishedAt: bl.publishedAt,
        });
      }
    }

    for (const til of tils) {
      const score = this.scoreItem(til.title, til.content, til.tags, queryWords);
      if (score > 0) {
        results.push({
          id: til.id,
          title: til.title,
          excerpt: til.content.substring(0, 150),
          slug: til.slug,
          tags: til.tags,
          contentType: 'til',
          score,
          publishedAt: til.publishedAt,
        });
      }
    }

    for (const note of notes) {
      const score = this.scoreItem(note.title, note.content, note.tags, queryWords);
      if (score > 0) {
        results.push({
          id: note.id,
          title: note.title,
          excerpt: note.content.substring(0, 150),
          slug: note.slug,
          tags: note.tags,
          contentType: 'note',
          score,
          publishedAt: note.publishedAt,
        });
      }
    }

    results.sort((a, b) => b.score - a.score);
    this.unifiedResults.set(results);
  }

  private scoreItem(
    title: string,
    content: string,
    tags: string[],
    queryWords: string[],
  ): number {
    let score = 0;
    score += this.searchInText(title, queryWords).score * 3;
    score += this.searchInText(content, queryWords).score;
    const matchingTags = tags.filter((tag) =>
      queryWords.some((word) => tag.toLowerCase().includes(word)),
    );
    score += matchingTags.length * 2;
    return score;
  }
  
  /**
   * Search for words in text and calculate relevance score
   */
  private searchInText(text: string, queryWords: string[]): { score: number } {
    const normalizedText = text.toLowerCase();
    let score = 0;
    
    for (const word of queryWords) {
      // Exact word match
      const exactMatches = (normalizedText.match(new RegExp(`\\b${word}\\b`, 'g')) || []).length;
      score += exactMatches * 2;
      
      // Partial match
      const partialMatches = (normalizedText.match(new RegExp(word, 'g')) || []).length;
      score += partialMatches - exactMatches; // Don't double count exact matches
    }
    
    return { score };
  }
  
  /**
   * Highlight matching words in text
   */
  private highlightText(text: string, queryWords: string[]): string {
    let highlightedText = text;
    
    for (const word of queryWords) {
      const regex = new RegExp(`(${word})`, 'gi');
      highlightedText = highlightedText.replace(regex, '<mark>$1</mark>');
    }
    
    return highlightedText;
  }
  
  /**
   * Extract a relevant excerpt with highlighted matches
   */
  private extractHighlightedExcerpt(content: string, queryWords: string[], maxLength: number = 200): string {
    const normalizedContent = content.toLowerCase();
    let bestExcerptStart = 0;
    let bestScore = 0;
    
    // Find the best excerpt position based on word density
    for (let i = 0; i < content.length - maxLength; i += 50) {
      const excerpt = normalizedContent.substring(i, i + maxLength);
      let score = 0;
      
      for (const word of queryWords) {
        score += (excerpt.match(new RegExp(word, 'g')) || []).length;
      }
      
      if (score > bestScore) {
        bestScore = score;
        bestExcerptStart = i;
      }
    }
    
    // Extract and highlight the best excerpt
    let excerpt = content.substring(bestExcerptStart, bestExcerptStart + maxLength);
    
    // Trim to word boundaries
    if (bestExcerptStart > 0) {
      excerpt = '...' + excerpt.substring(excerpt.indexOf(' ') + 1);
    }
    if (bestExcerptStart + maxLength < content.length) {
      excerpt = excerpt.substring(0, excerpt.lastIndexOf(' ')) + '...';
    }
    
    return this.highlightText(excerpt, queryWords);
  }
}