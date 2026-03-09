import {
  Component,
  input,
  signal,
  computed,
  effect,
  inject,
  Injector,
  PLATFORM_ID,
  DestroyRef,
  ChangeDetectionStrategy,
  afterNextRender,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { fromEvent, throttleTime } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LucideAngularModule, List } from 'lucide-angular';

const SCROLL_OFFSET_PX = 120;
const NAV_OFFSET_PX = 80;
const SCROLL_THROTTLE_MS = 100;

export interface TocItem {
  id: string;
  text: string;
  level: number;
}

@Component({
  selector: 'app-table-of-contents',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    @if (tocItems().length > 0) {
      <nav
        class="rounded-sm border border-zinc-800 bg-zinc-900/50 p-4"
        aria-label="Table of contents"
      >
        <h3
          class="mb-3 flex items-center gap-2 text-sm font-medium text-zinc-300"
        >
          <lucide-icon [img]="ListIcon" [size]="14" />
          Contents
        </h3>
        <ul class="space-y-0.5">
          @for (item of tocItems(); track item.id) {
            <li>
              <a
                [href]="'#' + item.id"
                class="block truncate rounded-sm px-2 py-1 text-xs no-underline transition-colors"
                [class]="
                  activeId() === item.id
                    ? 'bg-zinc-800 text-zinc-100'
                    : 'text-zinc-500 hover:text-zinc-300'
                "
                [style.padding-left.rem]="0.5 + (item.level - 2) * 0.75"
                (click)="scrollToElement($event, item.id)"
              >
                {{ item.text }}
              </a>
            </li>
          }
        </ul>
      </nav>
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TableOfContentsComponent {
  readonly content = input('');
  readonly selector = input('h2, h3');

  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);
  private readonly injector = inject(Injector);

  protected readonly activeId = signal('');

  protected readonly ListIcon = List;

  // Extract headings from HTML content string (works on server too)
  protected readonly tocItems = computed<TocItem[]>(() => {
    const html = this.content();
    if (!html) {
      return [];
    }

    const items: TocItem[] = [];
    const regex = /<h([2-3])\s+id="([^"]*)"[^>]*>(.*?)<\/h[2-3]>/gi;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(html)) !== null) {
      items.push({
        level: parseInt(match[1], 10),
        id: match[2],
        text: match[3].replace(/<[^>]*>/g, ''),
      });
    }

    return items;
  });

  constructor() {
    if (isPlatformBrowser(this.platformId)) {
      fromEvent(window, 'scroll')
        .pipe(throttleTime(SCROLL_THROTTLE_MS), takeUntilDestroyed())
        .subscribe(() => this.updateActiveSection());
    }

    // When content changes, wait for DOM render then recalculate active section
    effect(() => {
      const items = this.tocItems();
      if (items.length > 0 && isPlatformBrowser(this.platformId)) {
        afterNextRender(() => this.updateActiveSection(), { injector: this.injector });
      }
    });
  }

  private updateActiveSection(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    const items = this.tocItems();
    if (items.length === 0) {
      return;
    }

    const scrollPosition = window.scrollY + SCROLL_OFFSET_PX;
    let currentActiveId = '';

    for (const item of items) {
      const element = document.getElementById(item.id);
      if (element) {
        const top = element.getBoundingClientRect().top + window.scrollY;
        if (top <= scrollPosition) {
          currentActiveId = item.id;
        }
      }
    }

    this.activeId.set(currentActiveId);
  }

  protected scrollToElement(event: Event, id: string): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    event.preventDefault();
    const element = document.getElementById(id);
    if (element) {
      const top = element.getBoundingClientRect().top + window.scrollY - NAV_OFFSET_PX;
      window.scrollTo({ top, behavior: 'smooth' });
    }
  }
}
