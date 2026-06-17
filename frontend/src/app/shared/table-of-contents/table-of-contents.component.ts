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

const SCROLL_OFFSET_PX = 120;
const NAV_OFFSET_PX = 90;
const SCROLL_THROTTLE_MS = 100;

export interface TocItem {
  id: string;
  text: string;
  level: number;
}

@Component({
  selector: 'app-table-of-contents',
  template: `
    @if (tocItems().length > 0) {
      <nav aria-label="On this page">
        <h3 class="mb-3 font-mono text-[10px] uppercase tracking-[0.08em] text-fg-faint">
          On this page
        </h3>
        <ul>
          @for (item of tocItems(); track item.id) {
            <li>
              <a
                [href]="'#' + item.id"
                class="block border-l-2 py-[5px] pr-1 text-[12.5px] leading-[1.4] no-underline transition-colors"
                [class.border-brand]="activeId() === item.id"
                [class.text-brand]="activeId() === item.id"
                [class.border-border]="activeId() !== item.id"
                [class.text-fg-subtle]="activeId() !== item.id"
                [class.hover:text-fg-muted]="activeId() !== item.id"
                [style.padding-left.px]="item.level === 3 ? 24 : 12"
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
