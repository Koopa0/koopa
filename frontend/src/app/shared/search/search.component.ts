import {
  Component,
  inject,
  signal,
  ChangeDetectionStrategy,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  Search,
  X,
  SearchX,
  ArrowRight,
} from 'lucide-angular';
import { SearchService } from '../../core/services/search.service';
import { debounceTime, Subject } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { slideDown } from '../animations/fade-in.animation';
import type { ContentType } from '../../core/models';

/** Map ContentType to frontend route prefix */
const TYPE_ROUTE_MAP: Record<ContentType, string> = {
  article: '/articles',
  essay: '/essays',
  'build-log': '/build-logs',
  til: '/til',
  note: '/notes',
  bookmark: '/bookmarks',
  digest: '/digests',
};

@Component({
  selector: 'app-search',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  animations: [slideDown],
  template: `
    <div class="relative" role="search" aria-label="Article search">
      <div
        class="flex items-center gap-3 rounded-sm border border-zinc-700 bg-zinc-900 px-4 py-3"
      >
        <lucide-icon [img]="SearchIcon" [size]="18" class="text-zinc-500" />
        <input
          type="text"
          placeholder="Search articles..."
          class="flex-1 bg-transparent text-sm text-zinc-100 outline-hidden placeholder:text-zinc-500"
          [value]="searchQuery()"
          (input)="onSearchInput($event)"
          autocomplete="off"
          aria-label="Search articles"
        />
        @if (searchQuery()) {
          <button
            type="button"
            (click)="clearSearch()"
            class="text-zinc-500 hover:text-zinc-300"
            aria-label="Clear search"
          >
            <lucide-icon [img]="XIcon" [size]="16" />
          </button>
        }
      </div>

      @if (showResults()) {
        <div
          @slideDown
          class="absolute top-full right-0 left-0 z-50 mt-2 max-h-96 overflow-y-auto rounded-sm border border-zinc-700 bg-zinc-900 shadow-lg"
          role="listbox"
          aria-label="Search results"
        >
          @if (isSearching()) {
            <div
              class="flex items-center justify-center gap-2 p-8 text-zinc-400"
            >
              <div
                class="size-5 animate-spin rounded-full border-2 border-zinc-600 border-t-zinc-300"
              ></div>
              <span class="text-sm">Searching...</span>
            </div>
          } @else if (searchQuery() && !hasResults()) {
            <div class="flex flex-col items-center gap-2 p-8 text-zinc-400">
              <lucide-icon [img]="SearchXIcon" [size]="32" class="opacity-50" />
              <p class="text-sm">No results found for "{{ searchQuery() }}"</p>
            </div>
          } @else if (hasResults()) {
            <div class="p-2">
              @for (result of results(); track result.id) {
                <a
                  [routerLink]="getResultRoute(result.type, result.slug)"
                  class="flex items-center gap-3 rounded-sm px-3 py-3 text-zinc-300 no-underline transition-colors hover:bg-zinc-800"
                  (click)="clearSearch()"
                >
                  <div class="flex-1">
                    <h4 class="text-sm font-medium text-zinc-100">
                      {{ result.title }}
                    </h4>
                    @if (result.excerpt) {
                      <p class="mt-1 line-clamp-1 text-xs text-zinc-500">
                        {{ result.excerpt }}
                      </p>
                    }
                  </div>
                  <lucide-icon
                    [img]="ArrowRightIcon"
                    [size]="14"
                    class="text-zinc-600"
                  />
                </a>
              }
            </div>
          }
        </div>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SearchComponent {
  private readonly searchService = inject(SearchService);

  protected readonly searchQuery = signal('');
  protected readonly showResults = signal(false);
  private readonly searchSubject = new Subject<string>();

  protected readonly results = this.searchService.results;
  protected readonly isSearching = this.searchService.searching;
  protected readonly hasResults = this.searchService.hasResults;

  protected readonly SearchIcon = Search;
  protected readonly XIcon = X;
  protected readonly SearchXIcon = SearchX;
  protected readonly ArrowRightIcon = ArrowRight;

  constructor() {
    this.searchSubject
      .pipe(debounceTime(300), takeUntilDestroyed())
      .subscribe((query) => {
        this.searchService.search(query);
      });
  }

  protected onSearchInput(event: Event): void {
    const query = (event.target as HTMLInputElement).value;
    this.searchQuery.set(query);
    this.showResults.set(query.length > 0);
    this.searchSubject.next(query);
  }

  protected clearSearch(): void {
    this.searchQuery.set('');
    this.showResults.set(false);
    this.searchService.clearSearch();
  }

  protected getResultRoute(type: ContentType, slug: string): string {
    const prefix = TYPE_ROUTE_MAP[type] ?? '/articles';
    return `${prefix}/${slug}`;
  }
}
